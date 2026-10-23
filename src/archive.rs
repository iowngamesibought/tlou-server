//! The game's archive container, used inside the encrypted `netN.bin.psarc.crypt`
//! downloads, plus the two resource edits a private server needs: replacing
//! the literal service IPv4 strings in `netN.bin`, and rewriting the queue
//! server address in the campaign configuration text.
//!
//! Layout (as the game's own archives use it): 32-byte big-endian header
//! `PSAR | u16 major | u16 minor | "zlib" | u32 toc_size | u32 entry_size (30)
//! | u32 entry_count | u32 block_size | u32 flags`, then `entry_count` entries
//! `md5[16] | u32 first_block | u40 size | u40 offset`, then one u16 stored
//! length per block. Entry 0 is the manifest (newline-separated names, MD5
//! zero). A stored length of 0 means a full raw block; a stored length equal
//! to the block's plain length means raw; anything else is a zlib stream.

use md5::{Digest, Md5};

pub const HEADER_LEN: usize = 32;
pub const ENTRY_LEN: usize = 30;
pub const BLOCK_SIZE: usize = 65536;
pub const MAX_ENTRIES: usize = 4096;
pub const MAX_FILE: usize = 32 * 1024 * 1024;
pub const MAX_TOTAL: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated,
    Magic,
    Version(u16, u16),
    Compression,
    Layout(&'static str),
    Limit,
    Inflate,
    NameHash(String),
    Manifest,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub data: Vec<u8>,
}

fn be(b: &[u8], at: usize, n: usize) -> u64 {
    b[at..at + n]
        .iter()
        .fold(0u64, |acc, x| (acc << 8) | u64::from(*x))
}

pub fn name_md5(name: &str) -> [u8; 16] {
    Md5::digest(name.as_bytes()).into()
}

/// Parse and fully decompress an archive. Every named entry's MD5 must match
/// its manifest name; sizes are bounded by `MAX_FILE`/`MAX_TOTAL`.
pub fn read(archive: &[u8]) -> Result<Vec<Entry>, Error> {
    read_selected(archive, |_| true)
}

/// Like [`read`], but decompresses only the entries whose name `want`
/// accepts (a large archive's other entries are never inflated and do not
/// count towards `MAX_TOTAL`).
pub fn read_selected(archive: &[u8], want: impl Fn(&str) -> bool) -> Result<Vec<Entry>, Error> {
    if archive.len() < HEADER_LEN {
        return Err(Error::Truncated);
    }
    if &archive[..4] != b"PSAR" {
        return Err(Error::Magic);
    }
    let (major, minor) = (be(archive, 4, 2) as u16, be(archive, 6, 2) as u16);
    if (major, minor) != (1, 4) {
        return Err(Error::Version(major, minor));
    }
    if &archive[8..12] != b"zlib" {
        return Err(Error::Compression);
    }
    let toc_size = be(archive, 12, 4) as usize;
    let entry_size = be(archive, 16, 4) as usize;
    let count = be(archive, 20, 4) as usize;
    let block_size = be(archive, 24, 4) as usize;
    if entry_size != ENTRY_LEN || block_size != BLOCK_SIZE {
        return Err(Error::Layout("entry or block size"));
    }
    if count == 0 || count > MAX_ENTRIES {
        return Err(Error::Limit);
    }
    let table_end = HEADER_LEN + count * ENTRY_LEN;
    if toc_size < table_end || toc_size > archive.len() || !(toc_size - table_end).is_multiple_of(2)
    {
        return Err(Error::Layout("toc size"));
    }
    let blocks: Vec<usize> = archive[table_end..toc_size]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| usize::from(u16::from_be_bytes(*c)))
        .collect();
    let mut total = 0usize;
    // Entry i: its name hash and its decompressed bytes.
    let mut inflate = |i: usize| -> Result<([u8; 16], Vec<u8>), Error> {
        let e = &archive[HEADER_LEN + i * ENTRY_LEN..HEADER_LEN + (i + 1) * ENTRY_LEN];
        let md5: [u8; 16] = e[..16].try_into().unwrap();
        let first = be(e, 16, 4) as usize;
        let size = be(e, 20, 5) as usize;
        let mut offset = be(e, 25, 5) as usize;
        if size > MAX_FILE {
            return Err(Error::Limit);
        }
        total = total.checked_add(size).ok_or(Error::Limit)?;
        if total > MAX_TOTAL {
            return Err(Error::Limit);
        }
        let mut data = Vec::with_capacity(size);
        let mut block = first;
        while data.len() < size {
            let plain = (size - data.len()).min(BLOCK_SIZE);
            let stored = *blocks.get(block).ok_or(Error::Layout("block index"))?;
            let stored = if stored == 0 { BLOCK_SIZE } else { stored };
            let chunk = archive
                .get(offset..offset + stored)
                .ok_or(Error::Truncated)?;
            if stored == plain {
                data.extend_from_slice(chunk);
            } else {
                let out = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(chunk, plain)
                    .map_err(|_| Error::Inflate)?;
                if out.len() != plain {
                    return Err(Error::Inflate);
                }
                data.extend_from_slice(&out);
            }
            offset += stored;
            block += 1;
        }
        Ok((md5, data))
    };
    let manifest = String::from_utf8(inflate(0)?.1).map_err(|_| Error::Manifest)?;
    let names: Vec<&str> = if manifest.is_empty() {
        Vec::new()
    } else {
        manifest.split('\n').collect()
    };
    if names.len() != count - 1 {
        return Err(Error::Manifest);
    }
    let mut out = Vec::new();
    for (i, name) in names.into_iter().enumerate() {
        if !want(name) {
            continue;
        }
        let (md5, data) = inflate(i + 1)?;
        if name_md5(name) != md5 {
            return Err(Error::NameHash(name.to_owned()));
        }
        out.push(Entry {
            name: name.to_owned(),
            data,
        });
    }
    Ok(out)
}

/// The entry names in manifest order; only the manifest is decompressed.
pub fn names(archive: &[u8]) -> Result<Vec<String>, Error> {
    let names = std::cell::RefCell::new(Vec::new());
    read_selected(archive, |n| {
        names.borrow_mut().push(n.to_owned());
        false
    })?;
    Ok(names.into_inner())
}

fn push_be(out: &mut Vec<u8>, v: u64, n: usize) {
    for i in (0..n).rev() {
        out.push((v >> (8 * i)) as u8);
    }
}

/// Build an archive in the same shape as the CDN originals: manifest first
/// (names joined by `\n`, stored raw), each block zlib-compressed unless that
/// does not save space.
pub fn write(entries: &[Entry]) -> Result<Vec<u8>, Error> {
    if entries.is_empty() || entries.len() + 1 > MAX_ENTRIES {
        return Err(Error::Limit);
    }
    for e in entries {
        if e.name.is_empty() || e.name.contains('\n') || e.data.len() > MAX_FILE {
            return Err(Error::Manifest);
        }
    }
    let manifest = entries
        .iter()
        .map(|e| e.name.as_str())
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let mut files: Vec<([u8; 16], &[u8])> = vec![([0; 16], manifest.as_slice())];
    files.extend(
        entries
            .iter()
            .map(|e| (name_md5(&e.name), e.data.as_slice())),
    );

    // Stored blocks per file.
    let mut stored: Vec<Vec<Vec<u8>>> = Vec::with_capacity(files.len());
    for (index, (_, data)) in files.iter().enumerate() {
        let mut blocks = Vec::new();
        for chunk in data.chunks(BLOCK_SIZE) {
            let packed = miniz_oxide::deflate::compress_to_vec_zlib(chunk, 9);
            if index > 0 && packed.len() < chunk.len() {
                blocks.push(packed);
            } else {
                // A short raw block is told apart from zlib only by its stored
                // length equalling the plain length, which this writer keeps.
                blocks.push(chunk.to_vec());
            }
        }
        stored.push(blocks);
    }
    let block_count: usize = stored.iter().map(Vec::len).sum();
    let toc_size = HEADER_LEN + files.len() * ENTRY_LEN + 2 * block_count;

    let mut out = Vec::new();
    out.extend_from_slice(b"PSAR");
    push_be(&mut out, 1, 2);
    push_be(&mut out, 4, 2);
    out.extend_from_slice(b"zlib");
    push_be(&mut out, toc_size as u64, 4);
    push_be(&mut out, ENTRY_LEN as u64, 4);
    push_be(&mut out, files.len() as u64, 4);
    push_be(&mut out, BLOCK_SIZE as u64, 4);
    push_be(&mut out, 0, 4);
    let mut offset = toc_size;
    let mut first = 0usize;
    for ((md5, data), blocks) in files.iter().zip(&stored) {
        out.extend_from_slice(md5);
        push_be(&mut out, first as u64, 4);
        push_be(&mut out, data.len() as u64, 5);
        push_be(&mut out, offset as u64, 5);
        first += blocks.len();
        offset += blocks.iter().map(Vec::len).sum::<usize>();
    }
    for blocks in &stored {
        for b in blocks {
            // A full raw block is recorded as 0.
            push_be(&mut out, (b.len() % BLOCK_SIZE) as u64, 2);
        }
    }
    for blocks in &stored {
        for b in blocks {
            out.extend_from_slice(b);
        }
    }
    Ok(out)
}

/// One replaced IPv4 string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpEdit {
    pub offset: usize,
    pub old: String,
}

fn is_ipv4(s: &[u8]) -> bool {
    let parts: Vec<&[u8]> = s.split(|b| *b == b'.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty() && p.len() <= 3 && p.iter().all(u8::is_ascii_digit) && {
                let v: u32 = std::str::from_utf8(p).unwrap().parse().unwrap();
                v <= 255
            }
        })
}

/// Every distinct dotted IPv4 address stored as a whole NUL-delimited string
/// in `data`, in order of first appearance.
pub fn ipv4_literals(data: &[u8]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let start = i;
        while i < data.len() && (data[i].is_ascii_digit() || data[i] == b'.') {
            i += 1;
        }
        let whole = start == 0 || data[start - 1] == 0;
        if i > start && whole && data.get(i) == Some(&0) && is_ipv4(&data[start..i]) {
            let s = String::from_utf8(data[start..i].to_vec()).unwrap();
            if !found.contains(&s) {
                found.push(s);
            }
        }
        i += 1;
    }
    found
}

/// Replace every NUL-terminated occurrence of each address in `targets` with
/// `new`, in place. The data-compiler blob refers to these strings by
/// position, so the replacement must fit the old string; the remainder is
/// filled with NUL. Returns the edits made, or an error naming a target that
/// does not fit (nothing is changed then).
pub fn replace_ipv4(data: &mut [u8], targets: &[&str], new: &str) -> Result<Vec<IpEdit>, String> {
    if !is_ipv4(new.as_bytes()) {
        return Err(format!("{new:?} is not a dotted IPv4 address"));
    }
    let mut found = Vec::new();
    for target in targets {
        let needle: Vec<u8> = target.bytes().chain([0]).collect();
        let mut at = 0;
        while let Some(pos) = data[at..]
            .windows(needle.len())
            .position(|w| w == needle.as_slice())
        {
            let start = at + pos;
            // Must be a whole string, not the tail of a longer one.
            if start == 0 || !(data[start - 1].is_ascii_digit() || data[start - 1] == b'.') {
                found.push((start, *target));
            }
            at = start + needle.len();
        }
    }
    for (_, target) in &found {
        if new.len() > target.len() {
            return Err(format!(
                "{new} ({} characters) does not fit in place of {target} ({} characters); \
                 use an address of at most {} characters",
                new.len(),
                target.len(),
                target.len()
            ));
        }
    }
    found.sort();
    let mut edits = Vec::new();
    for (start, target) in found {
        data[start..start + target.len()].fill(0);
        data[start..start + new.len()].copy_from_slice(new.as_bytes());
        edits.push(IpEdit {
            offset: start,
            old: target.to_owned(),
        });
    }
    Ok(edits)
}

/// Rewrite `key value` lines of the campaign configuration. Keys not present
/// are appended; every other line is preserved byte-for-byte.
pub fn set_config_values(text: &str, values: &[(&str, &str)]) -> String {
    let mut seen = vec![false; values.len()];
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches(['\n', '\r']);
        let key = body.split(' ').next().unwrap_or("");
        if let Some(i) = values.iter().position(|(k, _)| *k == key) {
            seen[i] = true;
            out.push_str(values[i].0);
            out.push(' ');
            out.push_str(values[i].1);
            out.push_str(&line[body.len()..]);
            if !line.ends_with('\n') {
                // keep the original lack of a final newline
            }
        } else {
            out.push_str(line);
        }
    }
    for (i, (k, v)) in values.iter().enumerate() {
        if !seen[i] {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&format!("{k} {v}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_multi_block() {
        let big: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let entries = vec![
            Entry {
                name: "net10.bin".into(),
                data: big.clone(),
            },
            Entry {
                name: "tiny".into(),
                data: b"x".to_vec(),
            },
            Entry {
                name: "empty".into(),
                data: Vec::new(),
            },
        ];
        let archive = write(&entries).unwrap();
        assert_eq!(read(&archive).unwrap(), entries);
        assert_eq!(names(&archive).unwrap(), ["net10.bin", "tiny", "empty"]);
    }

    #[test]
    fn rejects_corruption() {
        let entries = vec![Entry {
            name: "a.bin".into(),
            data: vec![1; 1000],
        }];
        let archive = write(&entries).unwrap();
        for cut in [0, 10, 31, archive.len() - 1] {
            assert!(read(&archive[..cut]).is_err(), "cut {cut}");
        }
        let mut bad = archive.clone();
        bad[HEADER_LEN + ENTRY_LEN] ^= 1; // first named entry's MD5

        assert!(matches!(read(&bad), Err(Error::NameHash(_))));
        let mut bad = archive;
        bad[0] = b'X';
        assert_eq!(read(&bad), Err(Error::Magic));
    }

    // Addresses below are from the documentation ranges (RFC 5737).
    #[test]
    fn ip_replacement_in_place() {
        let mut d = b"xx\x00203.0.113.200\x00198.51.100.17\x00tail\x00198.51.100.170\x00".to_vec();
        let edits = replace_ipv4(&mut d, &["198.51.100.17", "203.0.113.200"], "10.0.0.5").unwrap();
        assert_eq!(edits.len(), 2, "198.51.100.170 is not a match");
        assert_eq!(&d[3..17], b"10.0.0.5\x00\x00\x00\x00\x00\x00");
        assert_eq!(&d[17..31], b"10.0.0.5\x00\x00\x00\x00\x00\x00");
        assert!(d.ends_with(b"198.51.100.170\x00"));
        let mut d = b"\x00192.0.2.10\x00".to_vec();
        let before = d.clone();
        assert!(replace_ipv4(&mut d, &["192.0.2.10"], "192.168.100.200").is_err());
        assert_eq!(d, before);
        assert!(replace_ipv4(&mut d, &["192.0.2.10"], "not.an.ip.x").is_err());
    }

    #[test]
    fn ipv4_literals_found_generically() {
        let d = b"a\x00192.0.2.10\x00v1.2.3.4\x001.2.3\x00198.51.100.7\x00\
                  192.0.2.10\x00x9.9.9.9\x00300.1.1.1\x00203.0.113.5";
        assert_eq!(ipv4_literals(d), ["192.0.2.10", "198.51.100.7"]);
    }

    #[test]
    fn config_rewrite_preserves_other_lines() {
        let t = "queue-server-addr 1.2.3.4\nqueue-server-port 7320\ninterval 10\n";
        let r = set_config_values(t, &[("queue-server-addr", "10.0.0.5"), ("extra", "1")]);
        assert_eq!(
            r,
            "queue-server-addr 10.0.0.5\nqueue-server-port 7320\ninterval 10\nextra 1\n"
        );
    }
}
