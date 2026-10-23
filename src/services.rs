//! The 0x11 service family on the ticket port (7320).
//!
//! Every connection: 88-byte hello naming a service -> 8-byte reply carrying
//! the counter for client frames -> encrypted frames (tlou-ticket-auth).
//! `ticket-server` submits one platform ticket and gets one 16-byte reply.
//! The others are line services: one ASCII command per frame, one reply per
//! frame, the reply terminated by NUL. Two rules hold for all line services:
//! always answer, and never close first (a server-initiated EOF is the
//! client's "disconnected" error path).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::codec::{HEADER_LEN, HELLO_LEN, Hello, HelloReply};
use crate::transport::{AuthSession, DenyAll, ServerTransport, TicketVerifier};

use crate::config::TicketTrust;
use crate::leaderboard::Leaderboard;
use crate::presence::Presence;
use crate::ticket::TransportTrust;
use crate::{info, warn};

const IDLE: Duration = Duration::from_secs(30);
/// Largest client frame accepted (a ticket is ~250 bytes, lines are short).
const MAX_FRAME: usize = HEADER_LEN + 0x4000;
/// The client's reply to the ticket. Retail 01.11 clients accept 16 zero
/// bytes; its meaning beyond "a valid frame" is not known.
const TICKET_REPLY: [u8; 16] = [0; 16];
/// Replies of services whose callers do one bounded 256-byte read.
const SMALL_REPLY: usize = 0x100;
const MAX_GAMES: usize = 1024;

pub struct Services {
    pub key: [u8; 16],
    pub trust: TicketTrust,
    pub leaderboard: Arc<Leaderboard>,
    pub presence: Arc<Presence>,
    pub games: Mutex<HashMap<String, Vec<String>>>,
    pub stats_path: Option<PathBuf>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn random_u32() -> u32 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    );
    h.finish() as u32
}

/// Read one whole frame (header + ciphertext) from the stream.
fn read_frame(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut wire = vec![0u8; HEADER_LEN];
    s.read_exact(&mut wire)?;
    let len = usize::from(u16::from_be_bytes([wire[2], wire[3]]));
    let pad = usize::from(wire[1]);
    if wire[0] != 0x33 || pad != len.wrapping_neg() & 3 || HEADER_LEN + len + pad > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a frame header",
        ));
    }
    wire.resize(HEADER_LEN + len + pad, 0);
    s.read_exact(&mut wire[HEADER_LEN..])?;
    Ok(wire)
}

fn is_eof(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
    )
}

fn first_token(line: &str) -> (&str, Vec<&str>) {
    let mut t = line.split_whitespace();
    (t.next().unwrap_or(""), t.collect())
}

impl Services {
    pub fn serve(self: Arc<Self>, listener: TcpListener) {
        info!(
            "services",
            "listening on {}",
            listener
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_default()
        );
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let me = self.clone();
            std::thread::spawn(move || {
                let peer = stream.peer_addr().ok();
                if let Err(e) = me.connection(stream) {
                    crate::debug!("services", "{peer:?}: connection ended: {e}");
                }
            });
        }
    }

    fn connection(&self, mut s: TcpStream) -> std::io::Result<()> {
        let peer = s.peer_addr()?;
        s.set_nodelay(true)?;
        s.set_read_timeout(Some(IDLE))?;
        s.set_write_timeout(Some(IDLE))?;
        let mut raw = [0u8; HELLO_LEN];
        s.read_exact(&mut raw)?;
        let hello = match Hello::parse(&raw) {
            Ok(h) => h,
            Err(e) => {
                warn!("services", "{peer}: not a service hello ({e:?}); closing");
                return Ok(());
            }
        };
        let seed = random_u32() & 0x3fff_ffff;
        if hello.service == "ticket-server" {
            return match self.trust {
                TicketTrust::Deny => self.ticket(s, peer, &hello, seed, DenyAll),
                TicketTrust::Transport => {
                    self.ticket(s, peer, &hello, seed, TransportTrust { last: None })
                }
            };
        }
        s.write_all(
            &HelloReply {
                server_choice: [0; 3],
                token: seed,
            }
            .encode(),
        )?;
        let mut t = ServerTransport::new(self.key, hello.client_nonce, seed, MAX_FRAME)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        let mut served = 0usize;
        loop {
            let wire = match read_frame(&mut s) {
                Ok(w) => w,
                Err(e) if is_eof(&e) => return Ok(()),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    crate::debug!(
                        "services",
                        "{peer} {}: idle after {served} command(s)",
                        hello.service
                    );
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            let request = match t.receive.open(&wire) {
                Ok(p) => p,
                Err(e) => {
                    warn!(
                        "services",
                        "{peer} {}: frame rejected ({e:?}); closing", hello.service
                    );
                    return Ok(());
                }
            };
            let text = String::from_utf8_lossy(&request);
            let line = text.trim_end_matches('\0');
            let (mut reply, note) = self.line(&hello.service, line, peer.ip());
            info!("services", "{peer} {}: {}", hello.service, note);
            if hello.service != "leaderboard-server" && reply.len() >= SMALL_REPLY {
                warn!(
                    "services",
                    "{} reply truncated to fit the client's buffer", hello.service
                );
                reply.truncate(SMALL_REPLY - 1);
            }
            let mut body = reply.into_bytes();
            body.push(0);
            let out = t
                .send
                .seal(&body)
                .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
            s.write_all(&out)?;
            served += 1;
        }
    }

    fn ticket<V: TicketVerifier>(
        &self,
        mut s: TcpStream,
        peer: SocketAddr,
        hello: &Hello,
        seed: u32,
        verifier: V,
    ) -> std::io::Result<()> {
        let (mut session, reply) =
            AuthSession::with_verifier(hello, self.key, seed, MAX_FRAME, verifier)
                .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        s.write_all(&reply.encode())?;
        let wire = read_frame(&mut s)?;
        match session.submit(&wire, now_secs()) {
            Ok(()) => {
                let id = session
                    .identity()
                    .map(|i| i.subject.clone())
                    .unwrap_or_default();
                self.presence.saw(peer.ip(), &id);
                info!(
                    "ticket",
                    "{peer}: ticket accepted for {id} (transport integrity only; platform signature not verified)"
                );
                let out = session
                    .seal_reply(&TICKET_REPLY)
                    .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
                s.write_all(&out)?;
            }
            Err(e) => {
                warn!("ticket", "{peer}: ticket rejected ({e:?}); closing");
                return Ok(());
            }
        }
        // Wait for the client to close; nothing further is expected.
        let mut sink = [0u8; 256];
        loop {
            match s.read(&mut sink) {
                Ok(0) | Err(_) => return Ok(()),
                Ok(n) => warn!(
                    "ticket",
                    "{peer}: unexpected {n} bytes after the ticket exchange"
                ),
            }
        }
    }

    /// One line-service command -> (reply body without NUL, log note).
    pub fn line(&self, service: &str, line: &str, ip: IpAddr) -> (String, String) {
        let (verb, args) = first_token(line);
        match service {
            "leaderboard-server" => self.leaderboard.handle(line),
            "heartbeat-server" => match (verb, args.first()) {
                ("heartbeat", Some(id)) => {
                    self.presence.saw(ip, id);
                    ("+0\n".into(), format!("heartbeat {id}"))
                }
                _ => ("+0\n".into(), format!("heartbeat line {line:?}")),
            },
            // The client tests buf[0] == '+' and then matches a ban-table name;
            // an empty body leaves its ban index at "not banned".
            "report-server" => (String::new(), format!("{verb} {args:?}: not banned")),
            "gamelist-server" => match verb {
                "game-add" if !args.is_empty() => {
                    let mut games = self.games.lock().unwrap_or_else(|e| e.into_inner());
                    if games.len() >= MAX_GAMES && !games.contains_key(args[0]) {
                        games.clear();
                    }
                    games.insert(
                        args[0].to_owned(),
                        args[1..].iter().map(|s| (*s).to_owned()).collect(),
                    );
                    (
                        "+0\n".into(),
                        format!("game-add {} roster={:?}", args[0], &args[1..]),
                    )
                }
                _ => (
                    "+0\n".into(),
                    format!("unrecognised gamelist line {line:?}"),
                ),
            },
            "facebook-server" => match verb {
                "facebook-set" => ("+0\n".into(), "facebook-set (ack)".into()),
                "facebook-get-fid" => (
                    "+0\n".repeat(args.len()),
                    format!("get-fid n={} (all unlinked)", args.len()),
                ),
                // Never fabricate player ids: the client hands them to the platform's
                // presence code, and a non-existent account crashed it.
                "facebook-get-npid" => (
                    String::new(),
                    format!("get-npid n={} (no matches)", args.len()),
                ),
                _ => ("+0\n".into(), format!("unknown facebook verb {verb:?}")),
            },
            "single-player-server" => {
                self.stat(line);
                ("+0\n".into(), format!("stat {args:?}"))
            }
            _ => (
                "+0\n".into(),
                format!("UNKNOWN service {service:?} line {line:?} (acked)"),
            ),
        }
    }

    fn stat(&self, line: &str) {
        let Some(path) = &self.stats_path else { return };
        let esc: String = line
            .chars()
            .flat_map(|c| match c {
                '"' => "\\\"".chars().collect::<Vec<_>>(),
                '\\' => "\\\\".chars().collect(),
                c if c.is_control() => format!("\\u{:04x}", c as u32).chars().collect(),
                c => vec![c],
            })
            .collect();
        let record = format!(
            "{{\"t\":\"{}\",\"line\":\"{esc}\"}}\n",
            crate::log::timestamp()
        );
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = f.write_all(record.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ticket;
    use crate::transport::Channel;

    fn services(trust: TicketTrust) -> Arc<Services> {
        Arc::new(Services {
            key: [7; 16],
            trust,
            leaderboard: Arc::new(Leaderboard::in_memory()),
            presence: Arc::default(),
            games: Mutex::default(),
            stats_path: None,
        })
    }

    fn start(svc: Arc<Services>) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        std::thread::spawn(move || svc.serve(l));
        a
    }

    fn hello(nonce: u32, service: &str) -> [u8; HELLO_LEN] {
        let mut h = [0u8; HELLO_LEN];
        h[0] = 0x11;
        h[4..8].copy_from_slice(&nonce.to_be_bytes());
        h[8..24].fill(0xee);
        h[24..24 + service.len()].copy_from_slice(service.as_bytes());
        h
    }

    fn connect(addr: SocketAddr, nonce: u32, service: &str) -> (TcpStream, Channel, Channel) {
        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(&hello(nonce, service)).unwrap();
        let mut r = [0u8; 8];
        c.read_exact(&mut r).unwrap();
        let reply = HelloReply::parse(&r).unwrap();
        let send = Channel::new([7; 16], reply.token, MAX_FRAME).unwrap();
        let recv = Channel::new([7; 16], nonce, MAX_FRAME).unwrap();
        (c, send, recv)
    }

    #[test]
    fn line_services_answer_with_nul_and_keep_counters() {
        let addr = start(services(TicketTrust::Deny));
        let (mut c, mut send, mut recv) = connect(addr, 0x1234, "leaderboard-server");
        for (req, want) in [
            ("leaderboard-update 406 alice 9 AAAAAQ==\n", "+0\n\0"),
            ("leaderboard-range 406 0 1 1\n", "+1\n\0"),
        ] {
            c.write_all(&send.seal(req.as_bytes()).unwrap()).unwrap();
            let wire = read_frame(&mut c).unwrap();
            assert_eq!(String::from_utf8(recv.open(&wire).unwrap()).unwrap(), want);
        }
        let (mut c, mut send, mut recv) = connect(addr, 9, "report-server");
        c.write_all(&send.seal(b"is-banned alice\n").unwrap())
            .unwrap();
        let reply = recv.open(&read_frame(&mut c).unwrap()).unwrap();
        assert_eq!(reply, b"\0", "not banned: buf[0] must not be '+'");
    }

    #[test]
    fn ticket_trust_policies() {
        let addr = start(services(TicketTrust::Deny));
        let (mut c, mut send, _) = connect(addr, 5, "ticket-server");
        c.write_all(&send.seal(&ticket::synthetic_ticket("alice")).unwrap())
            .unwrap();
        let mut b = [0u8; 1];
        assert_eq!(c.read(&mut b).unwrap(), 0, "deny closes without a reply");

        let svc = services(TicketTrust::Transport);
        let addr = start(svc.clone());
        let (mut c, mut send, mut recv) = connect(addr, 5, "ticket-server");
        c.write_all(&send.seal(&ticket::synthetic_ticket("alice")).unwrap())
            .unwrap();
        assert_eq!(
            recv.open(&read_frame(&mut c).unwrap()).unwrap(),
            TICKET_REPLY
        );
        assert!(svc.presence.recently("127.0.0.1".parse().unwrap(), "alice"));

        // A tampered frame is never answered.
        let (mut c, mut send, _) = connect(addr, 6, "ticket-server");
        let mut w = send.seal(&ticket::synthetic_ticket("alice")).unwrap();
        w[30] ^= 1;
        c.write_all(&w).unwrap();
        assert_eq!(c.read(&mut b).unwrap(), 0);
    }

    #[test]
    fn line_grammar() {
        let s = services(TicketTrust::Deny);
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        assert_eq!(s.line("heartbeat-server", "heartbeat bob", ip).0, "+0\n");
        assert!(s.presence.recently(ip, "bob"));
        assert_eq!(
            s.line("facebook-server", "facebook-get-fid a b c", ip).0,
            "+0\n+0\n+0\n"
        );
        assert_eq!(s.line("facebook-server", "facebook-get-npid 1 2", ip).0, "");
        assert_eq!(
            s.line("gamelist-server", "game-add bob.17 bob alice", ip).0,
            "+0\n"
        );
        assert_eq!(s.games.lock().unwrap()["bob.17"], ["bob", "alice"]);
        assert_eq!(
            s.line("single-player-server", "stat bob award-2f", ip).0,
            "+0\n"
        );
    }
}
