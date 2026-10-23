//! Which online ids have recently used the services from which address.
//! Fed by the session-manager hello, the ticket and the heartbeat line;
//! read by the HTTP side to decide whether a profile upload is kept.
//! In memory only: presence is ephemeral by nature.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a sighting keeps an address eligible for uploads under that id.
/// The client heartbeats far more often than this while online.
pub const WINDOW: Duration = Duration::from_secs(30 * 60);

#[derive(Default)]
pub struct Presence {
    seen: Mutex<HashMap<(IpAddr, String), Instant>>,
}

impl Presence {
    pub fn saw(&self, ip: IpAddr, online_id: &str) {
        if online_id.is_empty() {
            return;
        }
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        seen.retain(|_, t| now.duration_since(*t) < WINDOW);
        seen.insert((ip, online_id.to_owned()), now);
    }

    pub fn recently(&self, ip: IpAddr, online_id: &str) -> bool {
        let seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.get(&(ip, online_id.to_owned()))
            .is_some_and(|t| t.elapsed() < WINDOW)
    }

    pub fn count(&self) -> usize {
        let seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let mut ids: Vec<&String> = seen
            .iter()
            .filter(|(_, t)| t.elapsed() < WINDOW)
            .map(|((_, id), _)| id)
            .collect();
        ids.sort();
        ids.dedup();
        ids.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_by_address_and_id() {
        let p = Presence::default();
        let a: IpAddr = "10.0.0.2".parse().unwrap();
        let b: IpAddr = "10.0.0.3".parse().unwrap();
        p.saw(a, "alice");
        assert!(p.recently(a, "alice"));
        assert!(!p.recently(b, "alice"));
        assert!(!p.recently(a, "bob"));
        p.saw(a, "");
        assert_eq!(p.count(), 1);
    }
}
