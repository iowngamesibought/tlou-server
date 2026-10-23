//! Legacy bootstrap envelope, with caller-supplied keys and strict bounds.
//! This reproduces a game format, not a modern secure content distribution scheme.

use blowfish::Blowfish;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;

pub const MAX_CONTENT: usize = 32 * 1024 * 1024;
type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Key,
    Length,
    Limit,
    Integrity,
    Padding,
}

/// Keys are never part of Debug output or source fixtures.
pub struct Wrapper {
    cipher: Blowfish,
    mac: HmacSha1,
}

impl Wrapper {
    pub fn new(cipher_key: &[u8], mac_key: &[u8]) -> Result<Self, Error> {
        if !(4..=56).contains(&cipher_key.len()) || mac_key.is_empty() || mac_key.len() > 64 {
            return Err(Error::Key);
        }
        Ok(Self {
            cipher: Blowfish::new_from_slice(cipher_key).map_err(|_| Error::Key)?,
            mac: <HmacSha1 as Mac>::new_from_slice(mac_key).map_err(|_| Error::Key)?,
        })
    }

    fn size(length: usize) -> Result<usize, Error> {
        if length > MAX_CONTENT {
            return Err(Error::Limit);
        }
        Ok((length + 7) & !7)
    }

    /// Verify the padded plaintext MAC before returning any plaintext.
    /// Zero padding and exact envelope length are owned defensive policies.
    pub fn decode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        if input.len() < 24 {
            return Err(Error::Length);
        }
        let length = u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;
        let padded = Self::size(length)?;
        if input.len() != 24 + padded {
            return Err(Error::Length);
        }
        let mut plain = input[24..].to_vec();
        for block in plain.as_chunks_mut::<8>().0 {
            self.cipher.decrypt_block(block.into());
        }
        let mut mac = self.mac.clone();
        mac.update(&plain);
        mac.verify_slice(&input[4..24])
            .map_err(|_| Error::Integrity)?;
        if plain[length..].iter().any(|&b| b != 0) {
            return Err(Error::Padding);
        }
        plain.truncate(length);
        Ok(plain)
    }

    pub fn encode(&self, plain: &[u8]) -> Result<Vec<u8>, Error> {
        let padded = Self::size(plain.len())?;
        let mut result = vec![0; 24 + padded];
        result[..4].copy_from_slice(&(plain.len() as u32).to_be_bytes());
        result[24..24 + plain.len()].copy_from_slice(plain);
        let mut mac = self.mac.clone();
        mac.update(&result[24..]);
        result[4..24].copy_from_slice(&mac.finalize().into_bytes());
        for block in result[24..].as_chunks_mut::<8>().0 {
            self.cipher.encrypt_block(block.into());
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wrapper() -> Wrapper {
        Wrapper::new(b"synthetic-key", b"synthetic-mac-key").unwrap()
    }

    #[test]
    fn independent_synthetic_vectors() {
        for row in include_str!("../tests/fixtures/content-vectors.tsv").lines() {
            if row.starts_with('#') {
                continue;
            }
            let fields: Vec<_> = row.split('\t').collect();
            let plain = unhex(fields[1]);
            let raw = unhex(fields[2]);
            assert_eq!(wrapper().encode(&plain).unwrap(), raw, "{}", fields[0]);
            assert_eq!(wrapper().decode(&raw).unwrap(), plain);
        }
    }

    fn unhex(value: &str) -> Vec<u8> {
        if value == "-" {
            return vec![];
        }
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn standard_blowfish_known_answer() {
        let cipher: Blowfish = Blowfish::new_from_slice(&[0; 8]).unwrap();
        let mut block = [0u8; 8];
        cipher.encrypt_block((&mut block).into());
        assert_eq!(block.as_slice(), unhex("4ef997456198dd78"));
        cipher.decrypt_block((&mut block).into());
        assert_eq!(block, [0; 8]);
    }

    #[test]
    fn rfc2202_hmac_sha1_case_one() {
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&[0x0b; 20]).unwrap();
        mac.update(b"Hi There");
        assert_eq!(
            mac.finalize().into_bytes().as_slice(),
            unhex("b617318655057264e28bc0b6fb378c8ef146be00")
        );
    }

    #[test]
    fn every_prefix_and_trailing_bytes_rejected() {
        let raw = wrapper().encode(b"unaligned test").unwrap();
        for end in 0..raw.len() {
            assert!(wrapper().decode(&raw[..end]).is_err());
        }
        let mut extra = raw;
        extra.push(0);
        assert_eq!(wrapper().decode(&extra), Err(Error::Length));
    }

    #[test]
    fn corrupt_body_and_tag_never_release_plaintext() {
        let raw = wrapper().encode(b"unaligned test").unwrap();
        for i in 4..raw.len() {
            let mut changed = raw.clone();
            changed[i] ^= 1;
            assert_eq!(wrapper().decode(&changed), Err(Error::Integrity));
        }
        assert_eq!(
            Wrapper::new(b"wrong-key", b"synthetic-mac-key")
                .unwrap()
                .decode(&raw),
            Err(Error::Integrity)
        );
    }

    #[test]
    fn nonzero_padding_rejected_even_with_valid_mac() {
        let mut raw = wrapper().encode(b"abcd").unwrap();
        raw[..4].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(wrapper().decode(&raw), Err(Error::Padding));
    }

    #[test]
    fn header_is_not_authenticated_zero_suffix_is_ambiguous() {
        let mut raw = wrapper().encode(b"abc\0").unwrap();
        raw[..4].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(wrapper().decode(&raw).unwrap(), b"abc");
    }

    #[test]
    fn maximum_size_and_oversized_header() {
        let mut header = [0u8; 24];
        header[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(wrapper().decode(&header), Err(Error::Limit));
        assert_eq!(Wrapper::size(MAX_CONTENT), Ok(MAX_CONTENT));
        assert_eq!(Wrapper::size(MAX_CONTENT + 1), Err(Error::Limit));
    }

    #[test]
    fn key_bounds() {
        for n in [0, 1, 3, 57] {
            assert!(matches!(Wrapper::new(&vec![0; n], b"mac"), Err(Error::Key)));
        }
        assert!(matches!(Wrapper::new(b"okay", &[]), Err(Error::Key)));
        assert!(matches!(Wrapper::new(b"okay", &[0; 65]), Err(Error::Key)));
    }
}
