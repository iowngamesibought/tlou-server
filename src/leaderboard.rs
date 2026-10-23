//! leaderboard-server: persistent scores and the line grammar.
//!
//! Line grammar (not yet exercised by a retail client against this server):
//!   `leaderboard-update <board> <online_id> <score> <base64 blob>` -> `+0`
//!   `leaderboard-get <board> 1 <name>...` -> `+<rank0> <name> <score> <blob>` per known name
//!   `leaderboard-range <board> <start> <end> 1` -> `+<total>` then `+<name> <score> <blob>` rows;
//!     `range <board> 0 1` asks for the total only.
//! The blob is big-endian u32 slots with trailing zeros dropped by the
//! client: best_game, time_played, executions, deaths, rank, then four
//! mode-specific slots. It is stored decoded and re-encoded with at least
//! five slots, so a peer's "rank" column never falls back to standing.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const SLOTS: usize = 9;
const MIN_SLOTS: usize = 5;
const MAX_ROWS: usize = 64;
const HEADER: &str = "tlou-leaderboard-v1";

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for b in s.bytes() {
        let v = B64.iter().position(|x| *x == b)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

pub fn decode_blob(b64: &str) -> [u32; SLOTS] {
    let raw = b64_decode(b64).unwrap_or_default();
    let mut slots = [0u32; SLOTS];
    for (slot, c) in slots.iter_mut().zip(raw.as_chunks::<4>().0) {
        *slot = u32::from_be_bytes(*c);
    }
    slots
}

pub fn encode_blob(slots: &[u32; SLOTS]) -> String {
    let n = slots
        .iter()
        .rposition(|v| *v != 0)
        .map_or(MIN_SLOTS, |i| (i + 1).max(MIN_SLOTS));
    let bytes: Vec<u8> = slots[..n].iter().flat_map(|v| v.to_be_bytes()).collect();
    b64_encode(&bytes)
}

#[derive(Clone, Debug, PartialEq)]
struct Row {
    score: i64,
    slots: [u32; SLOTS],
}

pub struct Leaderboard {
    path: Option<PathBuf>,
    rows: Mutex<HashMap<(u32, String), Row>>,
}

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_graphic())
}

impl Leaderboard {
    pub fn in_memory() -> Self {
        Self {
            path: None,
            rows: Mutex::default(),
        }
    }

    pub fn open(path: &Path) -> Result<Self, String> {
        let mut rows = HashMap::new();
        if path.exists() {
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let mut lines = text.lines();
            if lines.next() != Some(HEADER) {
                return Err(format!("{}: not a {HEADER} file", path.display()));
            }
            for (n, line) in lines.enumerate() {
                let f: Vec<&str> = line.split('\t').collect();
                let bad = || format!("{} line {}: malformed", path.display(), n + 2);
                if f.len() != 3 + SLOTS {
                    return Err(bad());
                }
                let mut slots = [0u32; SLOTS];
                for (s, v) in slots.iter_mut().zip(&f[3..]) {
                    *s = v.parse().map_err(|_| bad())?;
                }
                rows.insert(
                    (f[0].parse().map_err(|_| bad())?, f[1].to_owned()),
                    Row {
                        score: f[2].parse().map_err(|_| bad())?,
                        slots,
                    },
                );
            }
        }
        Ok(Self {
            path: Some(path.to_owned()),
            rows: Mutex::new(rows),
        })
    }

    fn save(&self, rows: &HashMap<(u32, String), Row>) {
        let Some(path) = &self.path else { return };
        let mut keys: Vec<_> = rows.keys().collect();
        keys.sort();
        let mut text = format!("{HEADER}\n");
        for k in keys {
            let r = &rows[k];
            text.push_str(&format!("{}\t{}\t{}", k.0, k.1, r.score));
            for s in r.slots {
                text.push_str(&format!("\t{s}"));
            }
            text.push('\n');
        }
        let tmp = path.with_extension("tmp");
        let result = std::fs::File::create(&tmp)
            .and_then(|mut f| f.write_all(text.as_bytes()).and_then(|()| f.sync_all()))
            .and_then(|()| std::fs::rename(&tmp, path));
        if let Err(e) = result {
            crate::warn!("leaderboard", "could not save {}: {e}", path.display());
        }
    }

    fn ranked(rows: &HashMap<(u32, String), Row>, board: u32) -> Vec<(&String, &Row)> {
        let mut v: Vec<_> = rows
            .iter()
            .filter(|((b, _), _)| *b == board)
            .map(|((_, n), r)| (n, r))
            .collect();
        v.sort_by(|a, b| b.1.score.cmp(&a.1.score).then(a.0.cmp(b.0)));
        v
    }

    /// One command line -> (reply body, log note). The transport appends the NUL.
    pub fn handle(&self, line: &str) -> (String, String) {
        let t: Vec<&str> = line.split_whitespace().collect();
        let mut rows = self.rows.lock().unwrap_or_else(|e| e.into_inner());
        match t.first().copied() {
            Some("leaderboard-update") => {
                let parsed = (|| {
                    let board: u32 = t.get(1)?.parse().ok()?;
                    let name = *t.get(2)?;
                    let score: i64 = t.get(3)?.parse().ok()?;
                    valid_name(name).then_some((board, name, score))
                })();
                match parsed {
                    Some((board, name, score)) => {
                        let slots = decode_blob(t.get(4).copied().unwrap_or(""));
                        rows.insert((board, name.to_owned()), Row { score, slots });
                        self.save(&rows);
                        (
                            "+0\n".into(),
                            format!("stored board={board} {name} score={score}"),
                        )
                    }
                    None => ("+0\n".into(), "malformed update".into()),
                }
            }
            Some("leaderboard-get") => {
                let Some(board) = t.get(1).and_then(|b| b.parse::<u32>().ok()) else {
                    return (String::new(), "malformed get".into());
                };
                let ranked = Self::ranked(&rows, board);
                let mut out = String::new();
                let mut found = 0;
                for name in t.iter().skip(3).take(MAX_ROWS) {
                    if let Some(r) = rows.get(&(board, (*name).to_owned())) {
                        let rank0 = ranked.iter().filter(|(_, o)| o.score > r.score).count();
                        out.push_str(&format!(
                            "+{rank0} {name} {} {}\n",
                            r.score,
                            encode_blob(&r.slots)
                        ));
                        found += 1;
                    }
                }
                (
                    out,
                    format!(
                        "get board={board} names={} found={found}",
                        t.len().saturating_sub(3)
                    ),
                )
            }
            Some("leaderboard-range") => {
                let parsed = (|| {
                    Some((
                        t.get(1)?.parse::<u32>().ok()?,
                        t.get(2)?.parse::<usize>().ok()?,
                        t.get(3)?.parse::<usize>().ok()?,
                    ))
                })();
                let Some((board, start, end)) = parsed else {
                    return ("+0\n".into(), "malformed range".into());
                };
                let ranked = Self::ranked(&rows, board);
                let mut out = format!("+{}\n", ranked.len());
                if (start, end) == (0, 1) {
                    return (
                        out,
                        format!("range(total) board={board} total={}", ranked.len()),
                    );
                }
                let take = if end < start {
                    0
                } else {
                    (end - start + 1).min(MAX_ROWS)
                };
                for (name, r) in ranked.iter().skip(start).take(take) {
                    out.push_str(&format!("+{name} {} {}\n", r.score, encode_blob(&r.slots)));
                }
                (
                    out,
                    format!("range board={board} [{start},{end}] total={}", ranked.len()),
                )
            }
            other => ("+0\n".into(), format!("unknown verb {other:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip() {
        for n in 0..20u8 {
            let d: Vec<u8> = (0..n).collect();
            assert_eq!(b64_decode(&b64_encode(&d)).unwrap(), d);
        }
        assert_eq!(b64_encode(b"Man"), "TWFu");
        assert_eq!(b64_encode(b"Ma"), "TWE=");
        assert!(b64_decode("@@@").is_none());
    }

    #[test]
    fn blob_keeps_five_slots_and_long_forms() {
        let mut s = [0u32; SLOTS];
        s[0] = 4485;
        let b = encode_blob(&s);
        assert_eq!(b64_decode(&b).unwrap().len(), 20);
        let long = [4485, 3607, 42, 17, 2, 0, 5, 1, 0];
        assert_eq!(decode_blob(&encode_blob(&long)), long);
        assert_eq!(b64_decode(&encode_blob(&long)).unwrap().len(), 32);
    }

    #[test]
    fn grammar_and_persistence() {
        let dir = std::env::temp_dir().join(format!("tlou-lb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lb.tsv");
        let lb = Leaderboard::open(&path).unwrap();
        let blob = encode_blob(&[10, 20, 3, 4, 5, 0, 0, 0, 0]);
        lb.handle(&format!("leaderboard-update 406 alice 50 {blob}"));
        lb.handle("leaderboard-update 406 bob 70 AAAAAQ==");
        lb.handle("leaderboard-update 406 bad\tname 1");
        let lb = Leaderboard::open(&path).unwrap();
        let (r, _) = lb.handle("leaderboard-get 406 1 alice bob nobody");
        assert_eq!(
            r,
            format!("+1 alice 50 {blob}\n+0 bob 70 AAAAAQAAAAAAAAAAAAAAAAAAAAA=\n")
        );
        let (r, _) = lb.handle("leaderboard-range 406 0 1 1");
        assert_eq!(r, "+2\n");
        let (r, _) = lb.handle("leaderboard-range 406 0 9 1");
        assert!(r.starts_with("+2\n+bob 70 ") && r.contains("+alice 50 "));
        let (r, _) = lb.handle("leaderboard-range 999 0 9 1");
        assert_eq!(r, "+0\n");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
