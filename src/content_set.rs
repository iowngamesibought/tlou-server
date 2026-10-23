//! Hash-pinned local content snapshots and a deliberately small HTTP transport.
//! No upstream fetch, cryptographic wrapper generation, or game acceptance claim.
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::{Component, Path};
use std::time::{Duration, Instant};

pub const MAX_MANIFEST: usize = 128 * 1024;
pub const MAX_ROUTES: usize = 256;
pub const MAX_ASSET: usize = 32 * 1024 * 1024;
pub const MAX_TOTAL: usize = 128 * 1024 * 1024;
pub const MAX_HEADERS: usize = 16 * 1024;
pub const MAX_TARGET: usize = 2048;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn bounded_read(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid("file exceeds byte limit"));
    }
    Ok(bytes)
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn host_valid(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn path_valid(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= MAX_TARGET
        && path.len() > 1
        && path[1..].split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}

#[derive(Debug)]
struct Asset {
    bytes: Vec<u8>,
}

/// Immutable bytes verified together before the first listener is opened.
#[derive(Debug)]
pub struct Content {
    routes: BTreeMap<(String, String), Asset>,
}

impl Content {
    /// Manifest: UTF-8, `tlou-bootstrap-v1` first line, then six tab-separated
    /// fields: host (or `*` for any), URL path, relative file, lowercase
    /// SHA-256, original/prepared, provenance label. Labels record operator
    /// claims, not client verification.
    pub fn load(root: &Path, manifest: &Path) -> io::Result<Self> {
        let text = String::from_utf8(bounded_read(manifest, MAX_MANIFEST)?)
            .map_err(|_| invalid("manifest is not UTF-8"))?;
        let mut lines = text.lines();
        if lines.next() != Some("tlou-bootstrap-v1") {
            return Err(invalid("unsupported manifest header"));
        }
        let root = fs::canonicalize(root)?;
        if !root.is_dir() {
            return Err(invalid("asset root is not a directory"));
        }
        let mut routes = BTreeMap::new();
        let mut total = 0usize;
        for line in lines {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 6 || routes.len() == MAX_ROUTES {
                return Err(invalid("manifest field or route limit"));
            }
            let [host, url, file, expected, kind, provenance] =
                <[&str; 6]>::try_from(fields).unwrap();
            if !(host == "*" || host_valid(host))
                || !path_valid(url)
                || !matches!(kind, "original" | "prepared")
                || provenance.is_empty()
                || provenance.chars().any(char::is_control)
                || expected.len() != 64
                || !expected
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid("invalid manifest route or provenance"));
            }
            let relative = Path::new(file);
            if file.contains('\\')
                || file.contains(':')
                || relative.as_os_str().is_empty()
                || relative
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
                || file
                    .split('/')
                    .any(|c| c.is_empty() || c == "." || c == "..")
            {
                return Err(invalid("asset must be a plain relative path"));
            }
            let mut candidate = root.clone();
            for component in relative.components() {
                candidate.push(component);
                if is_reparse(&fs::symlink_metadata(&candidate)?) {
                    return Err(invalid("asset symlink or reparse point rejected"));
                }
            }
            let canonical = fs::canonicalize(&candidate)?;
            if !canonical.starts_with(&root) {
                return Err(invalid("asset escapes canonical root"));
            }
            let bytes = bounded_read(&canonical, MAX_ASSET.min(MAX_TOTAL - total))?;
            let digest = format!("{:x}", Sha256::digest(&bytes));
            if digest != expected {
                return Err(invalid("asset SHA-256 mismatch"));
            }
            total += bytes.len();
            if routes
                .insert((host.to_ascii_lowercase(), url.to_owned()), Asset { bytes })
                .is_some()
            {
                return Err(invalid("duplicate host/path route"));
            }
        }
        if routes.is_empty() {
            return Err(invalid("manifest has no assets"));
        }
        Ok(Self { routes })
    }

    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    pub fn total_bytes(&self) -> usize {
        self.routes.values().map(|asset| asset.bytes.len()).sum()
    }

    /// Bytes of the asset routed at this lowercase host (or `*`) and exact
    /// URL path.
    pub fn get(&self, host: &str, path: &str) -> Option<&[u8]> {
        self.routes
            .get(&(host.to_owned(), path.to_owned()))
            .or_else(|| self.routes.get(&("*".to_owned(), path.to_owned())))
            .map(|asset| asset.bytes.as_slice())
    }

    /// Bytes of the asset at this exact URL path, whatever host it is routed
    /// at; `None` when no route or more than one route has the path.
    pub fn get_path(&self, path: &str) -> Option<&[u8]> {
        let mut hits = self.routes.iter().filter(|((_, p), _)| p == path);
        match (hits.next(), hits.next()) {
            (Some((_, asset)), None) => Some(asset.bytes.as_slice()),
            _ => None,
        }
    }

    /// Reads exactly one bounded request, writes one response, then caller drops
    /// the stream. `Connection: close` is sent even for HTTP/1.1.
    pub fn serve(&self, stream: &mut TcpStream) -> io::Result<()> {
        stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
        let mut bytes = Vec::new();
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let request = loop {
            if bytes.len() == MAX_HEADERS {
                break Err(431);
            }
            let Some(remaining) = deadline
                .checked_duration_since(Instant::now())
                .filter(|duration| !duration.is_zero())
            else {
                break Err(408);
            };
            stream.set_read_timeout(Some(remaining))?;
            let mut chunk = [0u8; 1024];
            let capacity = chunk.len().min(MAX_HEADERS - bytes.len());
            match stream.read(&mut chunk[..capacity]) {
                Ok(0) => break Err(400),
                Ok(n) => {
                    bytes.extend_from_slice(&chunk[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        // Bytes after the sole request are never interpreted.
                        break parse_request(&bytes[..end + 4]);
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    break Err(408);
                }
                Err(error) => return Err(error),
            }
        };
        match request {
            Ok(request) => match self.get(&request.host, &request.path) {
                Some(bytes) => response(stream, 200, bytes, request.head),
                None => response(stream, 404, b"asset not in manifest\n", request.head),
            },
            Err(status) => response(stream, status, b"request rejected\n", false),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Request {
    host: String,
    path: String,
    head: bool,
}

fn parse_request(bytes: &[u8]) -> Result<Request, u16> {
    if !bytes.is_ascii() || bytes.len() > MAX_HEADERS {
        return Err(400);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| 400u16)?;
    let mut lines = text.split("\r\n");
    let words: Vec<_> = lines.next().ok_or(400u16)?.split(' ').collect();
    if words.len() != 3 || !matches!(words[2], "HTTP/1.0" | "HTTP/1.1") {
        return Err(400);
    }
    if !matches!(words[0], "GET" | "HEAD") {
        return Err(405);
    }
    let target = words[1];
    if target.len() > MAX_TARGET {
        return Err(414);
    }
    if target.bytes().any(|b| b <= 32 || b == 127 || b == b'#') {
        return Err(400);
    }
    // Query is opaque and ignored.
    // Percent-encoding in the path is rejected, never decoded or normalized.
    let path = target.split('?').next().ok_or(400u16)?;
    if !path_valid(path) {
        return Err(400);
    }
    let mut host = None;
    let mut length = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or(400u16)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| (b < 32 && b != b'\t') || b == 127)
        {
            return Err(400);
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return Err(400);
            }
            let hostname = if let Some((hostname, port)) = value.split_once(':') {
                if port.is_empty()
                    || !port.bytes().all(|b| b.is_ascii_digit())
                    || port.parse::<u16>().ok().filter(|p| *p > 0).is_none()
                {
                    return Err(400);
                }
                hostname
            } else {
                value
            };
            if !host_valid(hostname) {
                return Err(400);
            }
            host = Some(hostname.to_ascii_lowercase());
        } else if name.eq_ignore_ascii_case("content-length") {
            if length || value != "0" {
                return Err(400);
            }
            length = true;
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("expect")
        {
            return Err(400);
        }
    }
    Ok(Request {
        host: host.ok_or(400u16)?,
        path: path.to_owned(),
        head: words[0] == "HEAD",
    })
}

fn response(stream: &mut TcpStream, status: u16, body: &[u8], head: bool) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        414 => "URI Too Long",
        431 => "Request Header Fields Too Large",
        _ => "Bad Request",
    };
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n",
        body.len(),
        if status == 405 {
            "Allow: GET, HEAD\r\n"
        } else {
            ""
        }
    );
    let deadline = Instant::now() + REQUEST_TIMEOUT;
    write_until(stream, headers.as_bytes(), deadline)?;
    if !head {
        write_until(stream, body, deadline)?;
    }
    stream.flush()
}

fn write_until(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "response deadline"))?;
        stream.set_write_timeout(Some(remaining))?;
        let written = stream.write(bytes)?;
        if written == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "response closed"));
        }
        bytes = &bytes[written..];
    }
    Ok(())
}
