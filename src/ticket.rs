//! Best-effort reader for the platform login ticket carried by the
//! ticket-server frame, and the explicit "transport trust" verifier.
//!
//! The ticket grammar (u32 version, u32 size, then typed fields
//! `u16 type | u16 length | data` with 0x3000/0x3002 as nested body/footer)
//! is adapted from uc3-server's `ticket.rs` (MIT, "uc3-server contributors").
//! The signature is NOT verified: no platform trust material is pinned. The
//! online id read here is therefore a label for logs and upload scoping,
//! never proof of identity.

use crate::transport::{Identity, TicketVerifier, VerifyContext, VerifyError};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TicketInfo {
    pub version: u32,
    pub issuer_id: Option<u32>,
    pub online_id: Option<String>,
    pub service_id: Option<String>,
    pub expires_ms: Option<u64>,
}

struct Field<'a> {
    ty: u16,
    data: &'a [u8],
}

fn fields(mut b: &[u8]) -> Vec<Field<'_>> {
    let mut out = Vec::new();
    while b.len() >= 4 {
        let ty = u16::from_be_bytes([b[0], b[1]]);
        let len = usize::from(u16::from_be_bytes([b[2], b[3]]));
        if b.len() < 4 + len {
            break;
        }
        out.push(Field {
            ty,
            data: &b[4..4 + len],
        });
        b = &b[4 + len..];
    }
    out
}

fn text(d: &[u8]) -> String {
    let end = d.iter().position(|&c| c == 0).unwrap_or(d.len());
    String::from_utf8_lossy(&d[..end]).into_owned()
}

fn parse_at(ticket: &[u8]) -> Option<TicketInfo> {
    if ticket.len() < 8 {
        return None;
    }
    let version = u32::from_be_bytes(ticket[..4].try_into().ok()?);
    // Ticket versions seen on the platform are 2.x/3.x/4.x in the top byte.
    if !(0x2000_0000..0x5000_0000).contains(&version) {
        return None;
    }
    let top = fields(&ticket[8..]);
    let body = top.iter().find(|f| f.ty == 0x3000)?;
    // Body field order: serial, issuer id, issued, expires, user id, online
    // id, region, domain, service id, ...
    let f = fields(body.data);
    let get = |i: usize| f.get(i).map(|x| x.data);
    Some(TicketInfo {
        version,
        issuer_id: get(1).and_then(|d| d.try_into().ok().map(u32::from_be_bytes)),
        expires_ms: get(3).and_then(|d| d.try_into().ok().map(u64::from_be_bytes)),
        online_id: get(5).map(text).filter(|s| !s.is_empty()),
        service_id: get(8).map(text).filter(|s| !s.is_empty()),
    })
}

/// The frame payload is the raw ticket; a `u16` length prefix (as the sibling
/// UC3 client sends) is tolerated too.
pub fn parse(payload: &[u8]) -> Option<TicketInfo> {
    parse_at(payload).or_else(|| {
        let len = usize::from(u16::from_be_bytes(payload.get(..2)?.try_into().ok()?));
        (len + 2 == payload.len())
            .then(|| parse_at(&payload[2..]))
            .flatten()
    })
}

/// A valid online id: what the platform allows (3-16 of letters, digits, '-', '_').
pub fn valid_online_id(s: &str) -> bool {
    (3..=16).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Accepts any integrity-checked ticket whose structure names an online id.
/// The returned authority says plainly that nothing was verified.
pub struct TransportTrust {
    pub last: Option<TicketInfo>,
}

impl TicketVerifier for TransportTrust {
    fn verify(&mut self, ticket: &[u8], _: &VerifyContext) -> Result<Identity, VerifyError> {
        let info = parse(ticket).ok_or(VerifyError::Malformed)?;
        let online = info
            .online_id
            .clone()
            .filter(|s| valid_online_id(s))
            .ok_or(VerifyError::Malformed)?;
        self.last = Some(info);
        Ok(Identity {
            authority: "unverified-platform-ticket".into(),
            subject: online,
        })
    }
}

#[cfg(test)]
pub(crate) fn synthetic_ticket(online: &str) -> Vec<u8> {
    fn field(ty: u16, data: &[u8]) -> Vec<u8> {
        let mut v = ty.to_be_bytes().to_vec();
        v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
        v
    }
    let mut id = online.as_bytes().to_vec();
    id.resize(0x20, 0);
    let mut body = Vec::new();
    body.extend(field(8, &[0; 0x14]));
    body.extend(field(1, &5u32.to_be_bytes()));
    body.extend(field(7, &1u64.to_be_bytes()));
    body.extend(field(7, &2u64.to_be_bytes()));
    body.extend(field(2, &42u64.to_be_bytes()));
    body.extend(field(8, &id));
    body.extend(field(8, b"us\0\0"));
    body.extend(field(4, b"un\0\0"));
    body.extend(field(8, b"synthetic-service\0\0\0\0\0\0\0"));
    let mut t = 0x2101_0000u32.to_be_bytes().to_vec();
    let sec = field(0x3000, &body);
    t.extend_from_slice(&(sec.len() as u32).to_be_bytes());
    t.extend(sec);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_raw_and_prefixed() {
        let t = synthetic_ticket("Tester_01");
        let info = parse(&t).unwrap();
        assert_eq!(info.online_id.as_deref(), Some("Tester_01"));
        assert_eq!(info.issuer_id, Some(5));
        assert_eq!(info.service_id.as_deref(), Some("synthetic-service"));
        let mut p = (t.len() as u16).to_be_bytes().to_vec();
        p.extend(&t);
        assert_eq!(parse(&p), Some(info));
        assert!(parse(b"garbage!").is_none());
    }

    #[test]
    fn transport_trust_requires_an_online_id() {
        let ctx = VerifyContext {
            now_unix_seconds: 0,
        };
        let mut v = TransportTrust { last: None };
        assert_eq!(
            v.verify(&synthetic_ticket("Tester_01"), &ctx)
                .unwrap()
                .subject,
            "Tester_01"
        );
        assert_eq!(
            v.verify(&synthetic_ticket("x"), &ctx),
            Err(VerifyError::Malformed)
        );
        assert_eq!(
            v.verify(b"\x21\x01\0\0\0\0\0\0", &ctx),
            Err(VerifyError::Malformed)
        );
    }
}
