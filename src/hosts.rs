//! The host names to point at this server, read from the operator's own
//! executable (none are built into the server).
//!
//! The client downloads from a storage provider: `http://%s.<domain>`
//! templates name the provider's domain, fixed `http://<host>/...` URLs name
//! some of its hosts in full, and the remaining buckets are stored as bare
//! names (`<bucket>`, used as `<bucket>.<domain>`). A bucket is recognised as
//! a host-shaped string that shares its first label with one of the full
//! hosts. Uploads use the bare domain (path style), so it is listed too.
//! The provider's domain is the template domain the executable also names
//! full hosts under; a second template (the developer's own domain) is not.
//! Other plain-HTTP hosts of the executable are reported separately: this
//! server does not answer for them. HTTPS hosts are not listed at all: a
//! plain HTTP server cannot answer them.

/// NUL-delimited printable strings of at least 4 bytes.
fn strings(data: &[u8]) -> impl Iterator<Item = &str> {
    data.split(|b| *b == 0)
        .filter(|s| s.len() >= 4 && s.iter().all(|b| (0x20..0x7f).contains(b)))
        .map(|s| std::str::from_utf8(s).unwrap())
}

fn host_shaped(s: &str) -> bool {
    s.contains('.')
        && s.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Host names found in an executable.
#[derive(Debug, PartialEq)]
pub struct Hosts {
    /// The storage provider's names: point these at this server.
    pub served: Vec<String>,
    /// Other plain-HTTP hosts, not answered by this server.
    pub other: Vec<String>,
}

/// The host names, each list sorted.
pub fn from_executable(elf: &[u8]) -> Result<Hosts, String> {
    if !elf.starts_with(b"\x7fELF") {
        return Err("not an ELF file; pass the decrypted executable".into());
    }
    let mut domains = Vec::new();
    let mut fixed = Vec::new();
    for s in strings(elf) {
        let Some(rest) = s.strip_prefix("http://") else {
            continue;
        };
        let host = rest.split(['/', ':']).next().unwrap_or("");
        if let Some(domain) = host.strip_prefix("%s.") {
            if host_shaped(domain) && !domains.iter().any(|d| d == domain) {
                domains.push(domain.to_owned());
            }
        } else if host_shaped(host) && !fixed.iter().any(|h| h == host) {
            fixed.push(host.to_owned());
        }
    }
    // A template domain is the storage provider's only if the executable also
    // names some of its hosts in full; another template (the developer's own
    // domain) has none and is not served here.
    let (domains, foreign): (Vec<String>, Vec<String>) = domains
        .into_iter()
        .partition(|d| fixed.iter().any(|h| h.ends_with(&format!(".{d}"))));
    if domains.is_empty() {
        return Err("no download host template found; is this the game's main executable?".into());
    }
    let under = |h: &str| domains.iter().any(|d| h.ends_with(&format!(".{d}")));
    let mut names: Vec<String> = fixed.iter().filter(|h| under(h)).cloned().collect();
    let mut other: Vec<String> = fixed.iter().filter(|h| !under(h)).cloned().collect();
    other.extend(foreign);
    for domain in &domains {
        names.push(domain.clone());
        let firsts: Vec<&str> = fixed
            .iter()
            .filter(|h| h.ends_with(&format!(".{domain}")))
            .filter_map(|h| h.split('.').next())
            .collect();
        for s in strings(elf) {
            if host_shaped(s)
                && !s.ends_with(domain.as_str())
                && firsts.contains(&s.split('.').next().unwrap_or(""))
            {
                names.push(format!("{s}.{domain}"));
            }
        }
    }
    names.sort();
    names.dedup();
    other.sort();
    Ok(Hosts {
        served: names,
        other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reserved example names (RFC 2606).
    #[test]
    fn names_from_templates_fixed_urls_and_buckets() {
        let elf = b"\x7fELF\x02\x02\x00http://%s.storage.example\x00\
            http://%s.storage.example/up/%s\x00\
            http://%s.developer.example\x00\
            http://g1.config.storage.example/c.txt\x00\
            https://secure.example/me\x00\
            http://www.vendor.example/\x00\
            g1.content.prod\x00g1.content.dev\x00other.name.test\x00\
            Mixed.Case.x\x00g1.config.storage.example\x00";
        assert_eq!(
            from_executable(elf).unwrap(),
            Hosts {
                served: vec![
                    "g1.config.storage.example".into(),
                    "g1.content.dev.storage.example".into(),
                    "g1.content.prod.storage.example".into(),
                    "storage.example".into(),
                ],
                other: vec!["developer.example".into(), "www.vendor.example".into()],
            }
        );
        assert!(from_executable(b"not an elf").is_err());
        assert!(from_executable(b"\x7fELF\x00http://only.fixed.example/x\x00").is_err());
    }
}
