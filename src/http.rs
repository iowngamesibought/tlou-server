//! HTTP gateway (port 80): the content-delivery objects and the player
//! profile and game-record uploads.
//!
//! Routing is by path alone; the server never needs the content host names
//! (the operator points them here in DNS, and every object has a distinct
//! path):
//!   * Objects are addressed virtual-host style (`GET /<key>` on the bucket's
//!     own host) or path style (`PUT /<bucket>/<key>` on the provider's bare
//!     host); the client GETs profiles the first way and PUTs them the second.
//!     A first path segment that contains a dot and is followed by more of the
//!     path is a bucket name and is skipped.
//!   * Content comes only from the hash-pinned prepared manifest; nothing is
//!     fetched upstream.
//!   * An unknown path gets `200` with an empty body by default: retail
//!     clients carry on past optional objects answered this way.
//!   * `PUT profiles/<id>/profile.21` and `PUT games/<id>.<n>` are stored;
//!     every other PUT is acknowledged and dropped.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{Missing, ProfileUploads};
use crate::presence::Presence;
use crate::ticket::valid_online_id;
use crate::{info, warn};

const MAX_HEADERS: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(10);

pub struct Http {
    pub content: crate::content_set::Content,
    pub storage: PathBuf,
    pub presence: Arc<Presence>,
    pub uploads: ProfileUploads,
    pub missing: Missing,
}

#[derive(Debug, PartialEq)]
pub struct Request {
    pub method: String,
    /// The Host header, for logs only.
    pub host: String,
    pub path: String,
    pub body: Vec<u8>,
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Response {
    fn ok(content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            status: 200,
            content_type,
            body,
        }
    }
    fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: "application/octet-stream",
            body: Vec::new(),
        }
    }
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n").skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Read one request (headers, then a Content-Length body for PUT/POST).
pub fn read_request(s: &mut TcpStream) -> Result<Request, u16> {
    let deadline = Instant::now() + DEADLINE;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() > MAX_HEADERS {
            return Err(431);
        }
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(408u16)?;
        s.set_read_timeout(Some(left)).map_err(|_| 400u16)?;
        match s.read(&mut chunk) {
            Ok(0) => return Err(400),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(408),
        }
    };
    let head = std::str::from_utf8(&buf[..end])
        .map_err(|_| 400u16)?
        .to_owned();
    let mut words = head.split("\r\n").next().unwrap_or("").split(' ');
    let (method, target) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
    if !target.starts_with('/') || target.len() > 2048 {
        return Err(400);
    }
    let path = target.split('?').next().unwrap_or("/").to_owned();
    let host = header(&head, "host")
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let mut body = buf[end + 4..].to_vec();
    if matches!(method, "PUT" | "POST") {
        if header(&head, "transfer-encoding").is_some() {
            return Err(411);
        }
        let want: usize = header(&head, "content-length")
            .and_then(|v| v.parse().ok())
            .ok_or(411u16)?;
        if want > MAX_BODY {
            return Err(413);
        }
        while body.len() < want {
            let left = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(408u16)?;
            s.set_read_timeout(Some(left)).map_err(|_| 400u16)?;
            match s.read(&mut chunk) {
                Ok(0) => return Err(400),
                Ok(n) => body.extend_from_slice(&chunk[..n]),
                Err(_) => return Err(408),
            }
        }
        body.truncate(want);
    } else {
        body.clear();
    }
    Ok(Request {
        method: method.to_owned(),
        host,
        path,
        body,
    })
}

/// The object key of a virtual-host (`/<key>`) or path-style
/// (`/<bucket>/<key>`) request. Bucket names contain dots; first segments of
/// keys never do unless they are the whole key (a file name).
fn object_key(path: &str) -> &str {
    if let Some((first, rest)) = path.trim_start_matches('/').split_once('/')
        && first.contains('.')
        && !rest.is_empty()
    {
        return &path[1 + first.len()..];
    }
    path
}

/// `profiles/<id>/profile.21` -> id.
fn profile_key(key: &str) -> Option<&str> {
    let id = key
        .strip_prefix("/profiles/")?
        .strip_suffix("/profile.21")?;
    valid_online_id(id).then_some(id)
}

/// `games/<id>.<digits>` -> (id, file name).
fn game_key(key: &str) -> Option<(&str, &str)> {
    let name = key.strip_prefix("/games/")?;
    let (id, n) = name.split_once('.')?;
    (valid_online_id(id) && !n.is_empty() && n.len() <= 16 && n.bytes().all(|b| b.is_ascii_digit()))
        .then_some((id, name))
}

fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("upload");
    std::fs::File::create(&tmp)?.write_all(data)?;
    std::fs::rename(tmp, path)
}

impl Http {
    pub fn serve(self: Arc<Self>, listener: TcpListener) {
        info!(
            "http",
            "listening on {}",
            listener
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_default()
        );
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let me = self.clone();
            std::thread::spawn(move || {
                let Ok(peer) = s.peer_addr() else { return };
                let _ = s.set_write_timeout(Some(DEADLINE));
                let response = match read_request(&mut s) {
                    Ok(req) => me.respond(&req, peer.ip()),
                    Err(status) => Response::empty(status),
                };
                let reason = match response.status {
                    200 => "OK",
                    404 => "Not Found",
                    408 => "Request Timeout",
                    411 => "Length Required",
                    413 => "Payload Too Large",
                    431 => "Request Header Fields Too Large",
                    _ => "Bad Request",
                };
                let head = format!(
                    "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.status,
                    response.content_type,
                    response.body.len()
                );
                let _ = s
                    .write_all(head.as_bytes())
                    .and_then(|()| s.write_all(&response.body));
            });
        }
    }

    pub fn respond(&self, req: &Request, ip: IpAddr) -> Response {
        let key = object_key(&req.path);
        match req.method.as_str() {
            "PUT" | "POST" => self.upload(&req.host, key, &req.body, ip),
            "GET" | "HEAD" => {
                let mut r = self.get(&req.host, key, ip);
                if req.method == "HEAD" {
                    r.body.clear();
                }
                r
            }
            _ => Response::empty(400),
        }
    }

    fn get(&self, host: &str, key: &str, ip: IpAddr) -> Response {
        if let Some(bytes) = self.content.get_path(key) {
            info!("http", "{ip} GET {host}{key}: {} bytes", bytes.len());
            return Response::ok("application/octet-stream", bytes.to_vec());
        }
        if let Some(id) = profile_key(key)
            && let Ok(bytes) =
                std::fs::read(self.storage.join("profiles").join(id).join("profile.21"))
        {
            info!("http", "{ip} GET profile of {id}: {} bytes", bytes.len());
            return Response::ok("application/octet-stream", bytes);
        }
        match self.missing {
            Missing::Empty200 => {
                info!("http", "{ip} GET {host}{key}: not available, empty 200");
                Response::empty(200)
            }
            Missing::NotFound => {
                info!("http", "{ip} GET {host}{key}: not available, 404");
                Response::empty(404)
            }
        }
    }

    fn upload(&self, host: &str, key: &str, body: &[u8], ip: IpAddr) -> Response {
        let target = if let Some(id) = profile_key(key) {
            Some((
                id,
                self.storage.join("profiles").join(id).join("profile.21"),
            ))
        } else {
            game_key(key).map(|(id, name)| (id, self.storage.join("games").join(name)))
        };
        let Some((id, path)) = target else {
            warn!(
                "http",
                "{ip} PUT {host}{key}: not a profile or game record; acknowledged, not kept"
            );
            return Response::empty(200);
        };
        if self.uploads == ProfileUploads::Session && !self.presence.recently(ip, id) {
            warn!(
                "http",
                "{ip} PUT {key}: {id} has no recent session from this address; acknowledged, not kept"
            );
            return Response::empty(200);
        }
        match write_atomic(&path, body) {
            Ok(()) => info!("http", "{ip} PUT {key}: stored {} bytes", body.len()),
            Err(e) => warn!("http", "{ip} PUT {key}: could not store ({e})"),
        }
        Response::empty(200)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Host names below are reserved example names (RFC 2606).
    const BUCKET_HOST: &str = "bucket.one.example";
    const BARE_HOST: &str = "storage.example";

    fn gateway(dir: &Path, uploads: ProfileUploads) -> Http {
        std::fs::create_dir_all(dir.join("content")).unwrap();
        std::fs::write(dir.join("content/net10.bin.psarc.crypt"), b"NET10").unwrap();
        let digest = crate::log::hex(&sha2::Digest::finalize(
            <sha2::Sha256 as sha2::Digest>::new_with_prefix(b"NET10"),
        ));
        std::fs::write(
            dir.join("content/manifest.tsv"),
            format!(
                "tlou-bootstrap-v1\n*\t/net10.bin.psarc.crypt\tnet10.bin.psarc.crypt\t{digest}\tprepared\ttest\n"
            ),
        )
        .unwrap();
        Http {
            content: crate::content_set::Content::load(
                &dir.join("content"),
                &dir.join("content/manifest.tsv"),
            )
            .unwrap(),
            storage: dir.join("storage"),
            presence: Arc::default(),
            uploads,
            missing: Missing::Empty200,
        }
    }

    fn req(method: &str, host: &str, path: &str, body: &[u8]) -> Request {
        Request {
            method: method.into(),
            host: host.into(),
            path: path.into(),
            body: body.to_vec(),
        }
    }

    #[test]
    fn content_profiles_and_fallbacks() {
        let dir = std::env::temp_dir().join(format!("tlou-http-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let h = gateway(&dir, ProfileUploads::Session);
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        let get = |host: &str, path: &str| h.respond(&req("GET", host, path, b""), ip);
        let r = get(BUCKET_HOST, "/net10.bin.psarc.crypt");
        assert_eq!((r.status, r.body.as_slice()), (200, &b"NET10"[..]));
        let r = get(BARE_HOST, "/bucket.one/net10.bin.psarc.crypt");
        assert_eq!(r.body, b"NET10", "path-style addresses the same object");
        let r = get(BUCKET_HOST, "/unknown.crypt");
        assert_eq!((r.status, r.body.len()), (200, 0));

        // Without a session from this address the upload is not kept.
        let put = req(
            "PUT",
            BARE_HOST,
            "/bucket.one/profiles/alice/profile.21",
            b"PROFILE",
        );
        assert_eq!(h.respond(&put, ip).status, 200);
        assert_eq!(get(BUCKET_HOST, "/profiles/alice/profile.21").body.len(), 0);
        h.presence.saw(ip, "alice");
        h.respond(&put, ip);
        assert_eq!(
            get(BUCKET_HOST, "/profiles/alice/profile.21").body,
            b"PROFILE"
        );
        // Traversal-shaped keys never reach the file system.
        for path in [
            "/bucket.one/profiles/../../x/profile.21",
            "/bucket.one/games/alice.12/../x",
        ] {
            h.respond(&req("PUT", BARE_HOST, path, b"X"), ip);
        }
        assert!(!dir.join("x").exists() && !dir.join("storage/x").exists());
        h.respond(
            &req(
                "PUT",
                BARE_HOST,
                "/bucket.one/games/alice.1787116698",
                b"GAME",
            ),
            ip,
        );
        assert_eq!(
            std::fs::read(dir.join("storage/games/alice.1787116698")).unwrap(),
            b"GAME"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keys() {
        assert_eq!(
            profile_key("/profiles/Some_One/profile.21"),
            Some("Some_One")
        );
        assert_eq!(profile_key("/profiles/a/b/profile.21"), None);
        assert_eq!(game_key("/games/bob.123"), Some(("bob", "bob.123")));
        assert_eq!(game_key("/games/bob.12a"), None);
        assert_eq!(object_key("/b.c/k/x"), "/k/x");
        assert_eq!(
            object_key("/net10.bin.psarc.crypt"),
            "/net10.bin.psarc.crypt"
        );
        assert_eq!(object_key("/build/main/a.crypt"), "/build/main/a.crypt");
        assert_eq!(object_key("/a.b/"), "/a.b/");
    }
}
