//! Two small plaintext services.
//!
//! Location (port 7312): the client sends `get-location <id>\n`. The reply
//! grammar is the sibling UC3 client's (uc3-server location.rs:
//! `+ <lat> <lon> <code> <code> <code>`, 0/0 meaning "no location yet").
//! Retail 01.11 clients ask once per sign-in with this answer and do not
//! re-poll; the parser itself has not been read.
//!
//! Voice (port 7313): one connection after NAT detection; the client sends
//! `hello\n`, then `name <id> <n>\n`. Each read is answered `+OK\n` (the
//! client tests for a leading `'+'`); retail clients carry on after it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use crate::{debug, info};

pub fn location_answer(lat: f32, lon: f32) -> String {
    format!("+ {lat} {lon} 0 0 0\n")
}

fn each(
    listener: TcpListener,
    name: &'static str,
    f: impl Fn(TcpStream) + Send + Sync + Clone + 'static,
) {
    info!(
        name,
        "listening on {}",
        listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    );
    for stream in listener.incoming().flatten() {
        let f = f.clone();
        std::thread::spawn(move || f(stream));
    }
}

pub fn serve_location(listener: TcpListener, lat: f32, lon: f32) {
    each(listener, "location", move |mut s| {
        let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
        let mut buf = [0u8; 256];
        let Ok(n) = s.read(&mut buf) else { return };
        if n == 0 {
            return;
        }
        debug!(
            "location",
            "{:?}",
            String::from_utf8_lossy(&buf[..n]).trim_end()
        );
        let _ = s.write_all(location_answer(lat, lon).as_bytes());
        // Let the client close first.
        while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
    });
}

pub fn serve_voice(listener: TcpListener) {
    each(listener, "voice", |mut s| {
        let peer = s.peer_addr().ok();
        let _ = s.set_read_timeout(Some(Duration::from_secs(60)));
        let mut buf = [0u8; 4096];
        while let Ok(n) = s.read(&mut buf) {
            if n == 0 {
                break;
            }
            info!(
                "voice",
                "{peer:?} sent {:?}",
                String::from_utf8_lossy(&buf[..n.min(64)])
            );
            if s.write_all(b"+OK\n").is_err() {
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_round_trip() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        std::thread::spawn(move || serve_location(l, 1.5, -2.0));
        let mut c = TcpStream::connect(a).unwrap();
        c.write_all(b"get-location alice\n").unwrap();
        let mut buf = [0u8; 64];
        let n = c.read(&mut buf).unwrap();
        let tokens: Vec<&str> = std::str::from_utf8(&buf[..n])
            .unwrap()
            .split_whitespace()
            .collect();
        assert_eq!(tokens, ["+", "1.5", "-2", "0", "0", "0"]);
    }
}
