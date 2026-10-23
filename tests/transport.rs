use std::cell::Cell;
use std::rc::Rc;
use tlou_server::codec::{Hello, MAX_FRAME_LEN};
use tlou_server::transport::{
    AuthSession, AuthState, Channel, Error, Identity, ServerTransport, TicketVerifier,
    VerifyContext, VerifyError,
};

const KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

fn channel(counter: u32) -> Channel {
    Channel::new(KEY, counter, MAX_FRAME_LEN).unwrap()
}

fn hex(text: &str) -> Vec<u8> {
    if text == "-" {
        return vec![];
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn independent_synthetic_vectors() {
    let mut count = 0;
    for row in include_str!("fixtures/transport-vectors.tsv").lines() {
        if row.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = row.split('\t').collect();
        assert_eq!(hex(fields[1]), KEY);
        let counter = u32::from_str_radix(fields[2], 16).unwrap();
        let plaintext = hex(fields[3]);
        let wire = hex(fields[4]);
        let next = u32::from_str_radix(fields[5], 16).unwrap();
        let mut encoder = channel(counter);
        let mut decoder = channel(counter);
        assert_eq!(encoder.seal(&plaintext).unwrap(), wire, "{}", fields[0]);
        assert_eq!(decoder.open(&wire).unwrap(), plaintext, "{}", fields[0]);
        assert_eq!(encoder.counter(), next);
        assert_eq!(decoder.counter(), next);
        count += 1;
    }
    assert_eq!(count, 8);
}

#[test]
fn tag_and_ciphertext_tampering_are_terminal_and_do_not_advance() {
    let valid = channel(7).seal(b"synthetic-ticket-material").unwrap();
    for offset in 4..valid.len() {
        for bit in 0..8 {
            let mut tampered = valid.clone();
            tampered[offset] ^= 1 << bit;
            let mut receiver = channel(7);
            assert_eq!(receiver.open(&tampered), Err(Error::TagMismatch));
            assert!(receiver.is_closed());
            assert_eq!(receiver.counter(), 7);
            assert_eq!(receiver.open(&valid), Err(Error::Closed));
        }
    }
}

#[test]
fn wrong_key_counter_and_same_connection_replay_are_rejected() {
    let wire = channel(8).seal(b"ticket").unwrap();
    let mut wrong_key = Channel::new([0xff; 16], 8, MAX_FRAME_LEN).unwrap();
    assert_eq!(wrong_key.open(&wire), Err(Error::TagMismatch));
    assert_eq!(channel(9).open(&wire), Err(Error::TagMismatch));
    let mut receiver = channel(8);
    assert!(receiver.open(&wire).is_ok());
    assert_eq!(receiver.open(&wire), Err(Error::TagMismatch));
    assert_eq!(receiver.counter(), 9);
}

#[test]
fn both_directions_advance_independently_and_wrap() {
    let mut server = ServerTransport::new(KEY, u32::MAX, 100, MAX_FRAME_LEN).unwrap();
    let incoming = channel(100).seal(b"first").unwrap();
    assert_eq!(server.receive.open(&incoming).unwrap(), b"first");
    assert_eq!(server.receive.counter(), 101);
    assert_eq!(server.send.counter(), u32::MAX);
    let outgoing = server.send.seal(b"reply").unwrap();
    assert_eq!(channel(u32::MAX).open(&outgoing).unwrap(), b"reply");
    assert_eq!(server.send.counter(), 0);
    assert_eq!(server.receive.counter(), 101);
    assert_eq!(server.receive.open(&outgoing), Err(Error::TagMismatch));
    server.close();
    assert!(server.send.is_closed());
}

#[test]
fn malformed_truncated_extra_and_oversized_inputs_fail_closed() {
    let valid = channel(0).seal(b"abcde").unwrap();
    for prefix in 0..valid.len() {
        let mut decoder = channel(0);
        assert!(decoder.open(&valid[..prefix]).is_err());
        assert!(decoder.is_closed());
        assert_eq!(decoder.counter(), 0);
    }
    for (offset, value) in [(0, 0x34), (1, 4), (2, 0xff), (3, 0xff)] {
        let mut wire = valid.clone();
        wire[offset] = value;
        assert!(channel(0).open(&wire).is_err());
    }
    let mut extra = valid.clone();
    extra.push(0);
    assert_eq!(channel(0).open(&extra), Err(Error::TrailingBytes));
    let large = channel(0).seal(&[1; 100]).unwrap();
    assert!(Channel::new(KEY, 0, 88).unwrap().open(&large).is_err());
    assert!(Channel::new(KEY, 0, 87).is_err());
    assert_eq!(channel(0).seal(&vec![1; 65536]), Err(Error::TooLarge));
    let max = vec![0xa5; 65535];
    let wire = channel(0).seal(&max).unwrap();
    assert_eq!(wire.len(), MAX_FRAME_LEN);
    assert_eq!(channel(0).open(&wire).unwrap(), max);
}

#[test]
fn authenticated_nonzero_padding_is_dropped() {
    let mut wire = channel(0).seal(b"abcd").unwrap();
    // Body/tag still authenticate four bytes; the header now calls three of
    // them padding. Retail clients send such stale padding bytes.
    wire[1] = 3;
    wire[3] = 1;
    assert_eq!(channel(0).open(&wire).unwrap(), b"a");
}

#[test]
fn legacy_limit_headers_and_equal_seeds_are_not_authenticated() {
    let mut wire = channel(0).seal(b"x\0\0\0").unwrap();
    wire[1] = 3;
    wire[3] = 1;
    // Records an actual scheme limitation, not a security property we invent.
    assert_eq!(channel(0).open(&wire).unwrap(), b"x");
    let mut server = ServerTransport::new(KEY, 0, 0, MAX_FRAME_LEN).unwrap();
    let reflected = server.send.seal(b"synthetic").unwrap();
    assert_eq!(server.receive.open(&reflected).unwrap(), b"synthetic");
    // A fresh connection with the same seed can also accept the same frame.
    assert_eq!(channel(0).open(&reflected).unwrap(), b"synthetic");
}

fn hello() -> Hello {
    Hello {
        client_nonce: 44,
        service: "ticket-server".into(),
    }
}

#[test]
fn default_authentication_denies_integrity_valid_payload() {
    let (mut session, reply) = AuthSession::new(&hello(), KEY, 3, MAX_FRAME_LEN).unwrap();
    assert_eq!(reply.encode(), [0x22, 0, 0, 0, 0, 0, 0, 3]);
    let wire = channel(3).seal(b"not-a-platform-ticket").unwrap();
    assert_eq!(
        session.submit(&wire, 100),
        Err(Error::TicketRejected(VerifyError::Unavailable))
    );
    assert_eq!(session.state(), AuthState::Rejected);
    assert_eq!(session.identity(), None);
    assert_eq!(session.submit(&wire, 100), Err(Error::WrongState));
}

struct SyntheticVerifier {
    calls: Rc<Cell<usize>>,
    outcome: Result<Identity, VerifyError>,
}

impl TicketVerifier for SyntheticVerifier {
    fn verify(&mut self, ticket: &[u8], context: &VerifyContext) -> Result<Identity, VerifyError> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(ticket, b"synthetic");
        assert_eq!(context.now_unix_seconds, 100);
        self.outcome.clone()
    }
}

fn synthetic_session(
    outcome: Result<Identity, VerifyError>,
) -> (AuthSession<SyntheticVerifier>, Rc<Cell<usize>>) {
    let calls = Rc::new(Cell::new(0));
    let (session, _) = AuthSession::with_verifier(
        &hello(),
        KEY,
        3,
        MAX_FRAME_LEN,
        SyntheticVerifier {
            calls: calls.clone(),
            outcome,
        },
    )
    .unwrap();
    (session, calls)
}

#[test]
fn verifier_not_called_before_valid_integrity_or_for_empty_ticket() {
    let (mut session, calls) = synthetic_session(Err(VerifyError::Unavailable));
    let mut wire = channel(3).seal(b"synthetic").unwrap();
    wire[4] ^= 1;
    assert_eq!(session.submit(&wire, 100), Err(Error::TagMismatch));
    assert_eq!(calls.get(), 0);
    let (mut session, calls) = synthetic_session(Err(VerifyError::Unavailable));
    assert_eq!(
        session.submit(&channel(3).seal(b"").unwrap(), 100),
        Err(Error::EmptyTicket)
    );
    assert_eq!(calls.get(), 0);
}

#[test]
fn all_verifier_failures_are_terminal_and_never_bind_identity() {
    for error in [
        VerifyError::Unavailable,
        VerifyError::Malformed,
        VerifyError::UntrustedIssuer,
        VerifyError::Signature,
        VerifyError::Expired,
        VerifyError::WrongService,
        VerifyError::Replay,
    ] {
        let (mut session, calls) = synthetic_session(Err(error.clone()));
        assert_eq!(
            session.submit(&channel(3).seal(b"synthetic").unwrap(), 100),
            Err(Error::TicketRejected(error))
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(session.state(), AuthState::Rejected);
        assert!(session.identity().is_none());
    }
}

#[test]
fn synthetic_trusted_adapter_binds_once_and_close_clears_identity() {
    let identity = Identity {
        authority: "synthetic-test-only".into(),
        subject: "synthetic-subject".into(),
    };
    let (mut session, calls) = synthetic_session(Ok(identity.clone()));
    let wire = channel(3).seal(b"synthetic").unwrap();
    session.submit(&wire, 100).unwrap();
    assert_eq!(session.identity(), Some(&identity));
    assert_eq!(session.state(), AuthState::Authenticated);
    assert_eq!(session.submit(&wire, 100), Err(Error::WrongState));
    assert_eq!(calls.get(), 1);
    assert_eq!(session.state(), AuthState::Closed);
    assert!(session.identity().is_none());
}

#[test]
fn unsupported_service_and_empty_identity_fail() {
    let mut unknown = hello();
    unknown.service = "unknown-service".into();
    assert!(matches!(
        AuthSession::new(&unknown, KEY, 3, MAX_FRAME_LEN),
        Err(Error::UnsupportedService)
    ));
    let (mut session, _) = synthetic_session(Ok(Identity {
        authority: String::new(),
        subject: String::new(),
    }));
    assert_eq!(
        session.submit(&channel(3).seal(b"synthetic").unwrap(), 100),
        Err(Error::InvalidIdentity)
    );
    assert!(session.identity().is_none());
}

#[test]
fn reply_only_after_verifier_accepts() {
    let (mut denied, _) = AuthSession::new(&hello(), KEY, 3, MAX_FRAME_LEN).unwrap();
    assert_eq!(denied.seal_reply(&[0; 16]), Err(Error::WrongState));
    let _ = denied.submit(&channel(3).seal(b"synthetic").unwrap(), 100);
    assert_eq!(denied.seal_reply(&[0; 16]), Err(Error::WrongState));

    let (mut session, _) = synthetic_session(Ok(Identity {
        authority: "synthetic-test-only".into(),
        subject: "synthetic-subject".into(),
    }));
    assert_eq!(session.seal_reply(&[0; 16]), Err(Error::WrongState));
    session
        .submit(&channel(3).seal(b"synthetic").unwrap(), 100)
        .unwrap();
    // The reply direction is keyed by the client's hello nonce (44 here).
    let reply = session.seal_reply(&[0; 16]).unwrap();
    assert_eq!(channel(44).open(&reply).unwrap(), [0; 16]);
}
