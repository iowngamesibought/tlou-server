//! `key = value` configuration (a small TOML subset: comments with `#`,
//! optional double quotes, no tables). Relative paths resolve from the
//! configuration file's folder. Unknown keys are rejected so a typo cannot
//! silently fall back to a default.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketTrust {
    /// Reject every ticket (the library default; nobody can sign in).
    Deny,
    /// Accept a ticket whose legacy transport frame is intact, without
    /// verifying the platform signature. Suitable only for a private LAN
    /// where the platform already signed the player in.
    Transport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileUploads {
    /// Keep an upload only from an address that has a live service session
    /// under that online id.
    Session,
    /// Keep every well-formed upload.
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    /// Answer an unknown content path with `200 OK` and an empty body (retail
    /// clients carry on past optional objects answered this way; a 404 is
    /// not known to be safe).
    Empty200,
    NotFound,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub public_ip: Ipv4Addr,
    pub bind_ip: IpAddr,
    pub http_port: u16,
    pub ticket_port: u16,
    pub session_port: u16,
    pub location_port: u16,
    pub voice_port: u16,
    pub keys_file: PathBuf,
    pub content_dir: PathBuf,
    pub storage_dir: PathBuf,
    pub log_file: Option<PathBuf>,
    pub ticket_trust: TicketTrust,
    pub profile_uploads: ProfileUploads,
    pub missing_content: Missing,
    pub location: (f32, f32),
}

fn unquote(v: &str) -> &str {
    let v = v.trim();
    v.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(v)
}

pub fn parse_pairs(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected key = value", n + 1))?;
        // Strip a trailing comment outside quotes.
        let v = v.trim();
        let v = if let Some(rest) = v.strip_prefix('"') {
            match rest.find('"') {
                Some(end) => &v[..end + 2],
                None => return Err(format!("line {}: unterminated quote", n + 1)),
            }
        } else {
            v.split('#').next().unwrap_or("").trim()
        };
        out.push((k.trim().to_owned(), unquote(v).to_owned()));
    }
    Ok(out)
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        Self::parse(&text, base)
    }

    pub fn parse(text: &str, base: &Path) -> Result<Self, String> {
        let mut c = Config {
            public_ip: Ipv4Addr::UNSPECIFIED,
            bind_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            http_port: 80,
            ticket_port: 7320,
            session_port: 7314,
            location_port: 7312,
            voice_port: 7313,
            keys_file: base.join("keys.txt"),
            content_dir: base.join("content"),
            storage_dir: base.join("storage"),
            log_file: None,
            ticket_trust: TicketTrust::Deny,
            profile_uploads: ProfileUploads::Session,
            missing_content: Missing::Empty200,
            location: (1.0, 1.0),
        };
        let path = |v: &str| {
            let p = PathBuf::from(v);
            if p.is_absolute() { p } else { base.join(p) }
        };
        let port = |k: &str, v: &str| {
            v.parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("{k}: not a port number"))
        };
        let mut public_set = false;
        for (k, v) in parse_pairs(text)? {
            match k.as_str() {
                "public_ip" => {
                    c.public_ip = v
                        .parse()
                        .map_err(|_| format!("public_ip: {v:?} is not IPv4"))?;
                    public_set = true;
                }
                "bind_ip" => c.bind_ip = v.parse().map_err(|_| format!("bind_ip: {v:?}"))?,
                "http_port" => c.http_port = port(&k, &v)?,
                "ticket_port" => c.ticket_port = port(&k, &v)?,
                "session_port" => c.session_port = port(&k, &v)?,
                "location_port" => c.location_port = port(&k, &v)?,
                "voice_port" => c.voice_port = port(&k, &v)?,
                "keys_file" => c.keys_file = path(&v),
                "content_dir" => c.content_dir = path(&v),
                "storage_dir" => c.storage_dir = path(&v),
                "log_file" => c.log_file = Some(path(&v)),
                "ticket_trust" => {
                    c.ticket_trust = match v.as_str() {
                        "deny" => TicketTrust::Deny,
                        "transport" => TicketTrust::Transport,
                        _ => return Err("ticket_trust: expected \"deny\" or \"transport\"".into()),
                    }
                }
                "profile_uploads" => {
                    c.profile_uploads = match v.as_str() {
                        "session" => ProfileUploads::Session,
                        "any" => ProfileUploads::Any,
                        _ => return Err("profile_uploads: expected \"session\" or \"any\"".into()),
                    }
                }
                "missing_content" => {
                    c.missing_content = match v.as_str() {
                        "empty-200" => Missing::Empty200,
                        "404" => Missing::NotFound,
                        _ => {
                            return Err("missing_content: expected \"empty-200\" or \"404\"".into());
                        }
                    }
                }
                "location" => {
                    let parts: Vec<f32> = v
                        .split_whitespace()
                        .map(|p| p.parse::<f32>())
                        .collect::<Result<_, _>>()
                        .map_err(|_| "location: expected \"<lat> <lon>\"".to_string())?;
                    let [lat, lon] = parts[..] else {
                        return Err("location: expected \"<lat> <lon>\"".into());
                    };
                    if lat == 0.0 && lon == 0.0 {
                        return Err("location: 0 0 means \"no location\" to the client".into());
                    }
                    c.location = (lat, lon);
                }
                _ => return Err(format!("unknown setting {k:?}")),
            }
        }
        if !public_set || c.public_ip.is_unspecified() {
            return Err(
                "public_ip must be set to this machine's address as the console sees it".into(),
            );
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_rejects() {
        let c = Config::parse(
            "public_ip = \"10.0.0.5\" # lan\nticket_trust = transport\nlocation = \"2.5 -3\"\nstorage_dir = data\n",
            Path::new("/srv"),
        )
        .unwrap();
        assert_eq!(c.public_ip, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(c.ticket_trust, TicketTrust::Transport);
        assert_eq!(c.location, (2.5, -3.0));
        assert_eq!(c.storage_dir, Path::new("/srv").join("data"));
        assert_eq!(c.http_port, 80);
        assert!(Config::parse("", Path::new(".")).is_err());
        assert!(Config::parse("public_ip = 1.2.3.4\nbogus = 1\n", Path::new(".")).is_err());
        assert!(Config::parse("public_ip = 1.2.3.4\nlocation = 0 0\n", Path::new(".")).is_err());
        assert!(Config::parse("public_ip = 1.2.3.4\nhttp_port = 0\n", Path::new(".")).is_err());
    }
}
