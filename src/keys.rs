//! Title keys, read from the operator's own decrypted executable. Nothing in
//! this source tree contains key bytes: only the file offsets where each
//! supported build stores them, gated on the executable's exact SHA-256.

use sha2::{Digest, Sha256};
use std::path::Path;

pub struct Build {
    pub label: &'static str,
    pub elf_sha256: &'static str,
    /// 16-byte key of the framed service transport (ticket-server family).
    pub frame_key: usize,
    /// NUL-terminated Blowfish key of the `.crypt` content wrapper.
    pub content_cipher: usize,
    /// 64-byte HMAC-SHA1 key of the `.crypt` content wrapper.
    pub content_mac: usize,
}

pub const BUILDS: [Build; 2] = [
    Build {
        label: "01.00",
        elf_sha256: "2e44426f00fbb13f192548efa27b7101fb71807d3772ee6e3807ff5053fa94ff",
        frame_key: 0x00e6_e530,
        content_cipher: 0x00e4_a748,
        content_mac: 0x00ec_7dd0,
    },
    Build {
        label: "01.11",
        elf_sha256: "241e2b1bca43c97431a1aa7acd1b29a20d292bec7263ab8ca318b8a03538e592",
        frame_key: 0x00ea_1050,
        content_cipher: 0x00e7_c728,
        content_mac: 0x00ef_b040,
    },
];

const CIPHER_MAX: usize = 56;
const MAC_LEN: usize = 64;

pub struct Keys {
    pub build: String,
    pub frame: [u8; 16],
    pub content_cipher: Vec<u8>,
    pub content_mac: Vec<u8>,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keys {{ build: {:?}, .. }}", self.build)
    }
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

impl Keys {
    /// Extract from a decrypted executable (ELF) of a supported build.
    pub fn from_elf(elf: &[u8]) -> Result<Self, String> {
        let digest = crate::log::hex(&Sha256::digest(elf));
        let build = BUILDS
            .iter()
            .find(|b| b.elf_sha256 == digest)
            .ok_or_else(|| {
                format!(
                    "executable SHA-256 {digest} is not a supported build \
                     (01.00 or 01.11, decrypted main executable)"
                )
            })?;
        let frame: [u8; 16] = elf[build.frame_key..build.frame_key + 16]
            .try_into()
            .unwrap();
        let region = &elf[build.content_cipher..build.content_cipher + CIPHER_MAX + 1];
        let end = region
            .iter()
            .position(|b| *b == 0)
            .ok_or("content cipher key not terminated")?;
        let content_cipher = region[..end].to_vec();
        let content_mac = elf[build.content_mac..build.content_mac + MAC_LEN].to_vec();
        if content_cipher.len() < 4 {
            return Err("content cipher key too short".into());
        }
        Ok(Keys {
            build: build.label.to_owned(),
            frame,
            content_cipher,
            content_mac,
        })
    }

    pub fn to_text(&self) -> String {
        format!(
            "# tlou-server keys, extracted from the operator's own executable. Keep private.\n\
             build = {}\nframe = {}\ncontent_cipher = {}\ncontent_mac = {}\n",
            self.build,
            crate::log::hex(&self.frame),
            crate::log::hex(&self.content_cipher),
            crate::log::hex(&self.content_mac)
        )
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading keys file {}: {e}", path.display()))?;
        let mut build = None;
        let mut frame = None;
        let mut cipher = None;
        let mut mac = None;
        for (k, v) in crate::config::parse_pairs(&text)? {
            let bytes = || unhex(&v).ok_or_else(|| format!("keys file: {k} is not hex"));
            match k.as_str() {
                "build" => build = Some(v.clone()),
                "frame" => {
                    frame = Some(
                        <[u8; 16]>::try_from(bytes()?)
                            .map_err(|_| "keys file: frame must be 16 bytes".to_string())?,
                    )
                }
                "content_cipher" => cipher = Some(bytes()?),
                "content_mac" => mac = Some(bytes()?),
                _ => return Err(format!("keys file: unknown entry {k:?}")),
            }
        }
        Ok(Keys {
            build: build.ok_or("keys file: missing build")?,
            frame: frame.ok_or("keys file: missing frame")?,
            content_cipher: cipher.ok_or("keys file: missing content_cipher")?,
            content_mac: mac.ok_or("keys file: missing content_mac")?,
        })
    }

    pub fn wrapper(&self) -> Result<crate::content::Wrapper, String> {
        crate::content::Wrapper::new(&self.content_cipher, &self.content_mac)
            .map_err(|e| format!("content keys rejected: {e:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_executable_is_refused() {
        assert!(Keys::from_elf(b"not an executable").is_err());
    }

    #[test]
    fn text_round_trip_with_synthetic_keys() {
        let k = Keys {
            build: "01.11".into(),
            frame: [7; 16],
            content_cipher: b"synthetic".to_vec(),
            content_mac: vec![9; 64],
        };
        let dir = std::env::temp_dir().join(format!("tlou-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("keys.txt");
        std::fs::write(&p, k.to_text()).unwrap();
        let l = Keys::load(&p).unwrap();
        assert!(
            !format!("{l:?}").contains("07"),
            "Debug never prints key bytes"
        );
        assert_eq!(
            (l.frame, l.content_cipher, l.content_mac),
            (k.frame, k.content_cipher, k.content_mac)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
