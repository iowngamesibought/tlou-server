use tlou_server::codec::*;

// A hello in the shape a client sends: nonce and service name set, all other
// bytes synthetic (zero).
fn hello() -> [u8; 88] {
    let mut h = [0; 88];
    h[..8].copy_from_slice(&[0x11, 0, 0, 0, 0x27, 0xab, 0x50, 0x86]);
    h[24..38].copy_from_slice(b"ticket-server\0");
    h
}

// Actual captured prefix 33 02 00 fa; tag/body are SYNTHETIC zeros.
// This is an independent length/framing vector, NOT a valid crypto/ticket vector.
fn captured_prefix_synthetic_body() -> Vec<u8> {
    let mut frame = vec![0; 272];
    frame[..4].copy_from_slice(&[0x33, 2, 0, 0xfa]);
    frame
}

#[test]
fn source_hello_fields_and_ignored_residue() {
    let mut bytes = hello();
    bytes[1..4].fill(0xff); // Reserved acceptance is deliberate policy.
    bytes[8..24].fill(0xff);
    bytes[38..88].fill(0xff);
    let parsed = Hello::parse(&bytes).unwrap();
    assert_eq!(parsed.client_nonce, 0x27ab5086);
    assert_eq!(parsed.service, "ticket-server");
}

#[test]
fn invalid_hello_fields() {
    let mut bytes = hello();
    bytes[0] = 0;
    assert_eq!(Hello::parse(&bytes), Err(Error::InvalidMagic));
    bytes[0] = 0x11;
    bytes[24..88].fill(b'a');
    assert_eq!(Hello::parse(&bytes), Err(Error::MissingServiceTerminator));
    bytes[87] = 0;
    assert_eq!(Hello::parse(&bytes).unwrap().service.len(), 63);
    bytes[24] = 0x80;
    assert_eq!(Hello::parse(&bytes), Err(Error::NonAsciiService));
}

#[test]
fn reply_fixed_vectors() {
    // A server reply with token 0 and server choice 0.
    assert_eq!(
        HelloReply {
            server_choice: [0; 3],
            token: 0
        }
        .encode(),
        [0x22, 0, 0, 0, 0, 0, 0, 0]
    );
    // Deliberately nonzero synthetic values independently check byte order.
    let wire = [0x22, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78];
    let reply = HelloReply::parse(&wire).unwrap();
    assert_eq!(reply.token, 0x12345678);
    assert_eq!(reply.server_choice, [0xab, 0xcd, 0xef]);
    assert_eq!(reply.encode(), wire);
    assert_eq!(HelloReply::parse(&[0; 8]), Err(Error::InvalidMagic));
}

#[test]
fn source_frame_length_at_every_tcp_split() {
    let bytes = captured_prefix_synthetic_body();
    for split in 0..bytes.len() {
        let mut d = Decoder::frames(MAX_FRAME_LEN).unwrap();
        assert_eq!(d.consume(&bytes[..split]).unwrap(), (split, None));
        let (used, event) = d.consume(&bytes[split..]).unwrap();
        assert_eq!(used, bytes.len() - split);
        let Some(Event::Frame(frame)) = event else {
            panic!("missing frame");
        };
        assert_eq!(frame.plaintext_len(), 250);
        assert_eq!(frame.ciphertext().len(), 252);
        assert_eq!(frame.tag(), &[0; 16]);
        assert_eq!(frame.encode(), bytes);
        assert_eq!(d.finish(), Ok(()));
    }
}

#[test]
fn fragmented_hello_then_coalesced_frames() {
    let mut d = Decoder::client_stream(2048).unwrap();
    let h = hello();
    for byte in &h[..87] {
        assert_eq!(d.consume(&[*byte]).unwrap(), (1, None));
    }
    assert!(matches!(
        d.consume(&h[87..]).unwrap(),
        (1, Some(Event::Hello(_)))
    ));
    let frame = captured_prefix_synthetic_body();
    let twice = [frame.as_slice(), frame.as_slice()].concat();
    assert!(matches!(
        d.consume(&twice).unwrap(),
        (272, Some(Event::Frame(_)))
    ));
    assert!(matches!(
        d.consume(&twice[272..]).unwrap(),
        (272, Some(Event::Frame(_)))
    ));
    assert_eq!(d.buffered_len(), 0);
}

#[test]
fn coalesced_hello_stops_before_first_frame() {
    let bytes = [
        hello().as_slice(),
        captured_prefix_synthetic_body().as_slice(),
    ]
    .concat();
    let mut d = Decoder::client_stream(2048).unwrap();
    assert!(matches!(
        d.consume(&bytes).unwrap(),
        (88, Some(Event::Hello(_)))
    ));
    assert!(matches!(
        d.consume(&bytes[88..]).unwrap(),
        (272, Some(Event::Frame(_)))
    ));
}

#[test]
fn header_rejection_is_terminal() {
    for (offset, value, error) in [
        (0, 0x22, Error::InvalidMagic),
        (1, 4, Error::InvalidPadding),
        (1, 1, Error::InvalidPadding),
    ] {
        let mut bytes = captured_prefix_synthetic_body();
        bytes[offset] = value;
        let mut d = Decoder::frames(MAX_FRAME_LEN).unwrap();
        assert_eq!(d.consume(&bytes), Err(error));
        assert_eq!(d.buffered_len(), 0);
        assert_eq!(d.consume(&[]), Err(Error::Closed));
        assert_eq!(d.finish(), Err(Error::Closed));
    }
}

#[test]
fn limit_checked_before_body_is_buffered() {
    let mut d = Decoder::frames(271).unwrap();
    assert_eq!(
        d.consume(&captured_prefix_synthetic_body()),
        Err(Error::FrameTooLarge)
    );
    assert_eq!(d.buffered_len(), 0);
    assert!(matches!(Decoder::frames(87), Err(Error::InvalidLimit)));
    assert!(matches!(
        Decoder::frames(MAX_FRAME_LEN + 1),
        Err(Error::InvalidLimit)
    ));
}

#[test]
fn all_length_values_have_bounded_canonical_framing() {
    for len in 0..=u16::MAX {
        // Independent integer arithmetic: round up to 4.
        let body = usize::from(len).div_ceil(4) * 4;
        let frame = OpaqueFrame::new(len, [0; 16], vec![0; body]).unwrap();
        let bytes = frame.encode();
        assert!(bytes.len() <= MAX_FRAME_LEN);
        assert_eq!(bytes.len(), 20 + body);
        assert_eq!(usize::from(bytes[1]), body - usize::from(len));
        assert_eq!(&bytes[2..4], &len.to_be_bytes());
    }
}

#[test]
fn max_and_zero_length_frames() {
    for (header, body) in [([0x33, 1, 0xff, 0xff], 65536), ([0x33, 0, 0, 0], 0)] {
        let mut bytes = vec![0; 20 + body];
        bytes[..4].copy_from_slice(&header);
        let mut d = Decoder::frames(MAX_FRAME_LEN).unwrap();
        assert!(
            matches!(d.consume(&bytes).unwrap(), (n, Some(Event::Frame(_))) if n == bytes.len())
        );
    }
}

#[test]
fn eof_detects_each_truncated_position_and_closes() {
    let bytes = [
        hello().as_slice(),
        captured_prefix_synthetic_body().as_slice(),
    ]
    .concat();
    for end in 0..bytes.len() {
        let mut d = Decoder::client_stream(MAX_FRAME_LEN).unwrap();
        let mut used = 0;
        while used < end {
            used += d.consume(&bytes[used..end]).unwrap().0;
        }
        assert_eq!(
            d.finish(),
            if end == 88 {
                Ok(())
            } else {
                Err(Error::Truncated)
            }
        );
        assert_eq!(d.consume(&[]), Err(Error::Closed));
    }
}

#[test]
fn opaque_wrapper_never_claims_tag_validity() {
    assert_eq!(
        OpaqueFrame::new(1, [0; 16], vec![0]),
        Err(Error::InvalidCiphertextLength)
    );
    let mut bytes = captured_prefix_synthetic_body();
    bytes[4..20].fill(0xff);
    let mut d = Decoder::frames(MAX_FRAME_LEN).unwrap();
    let (_, Some(Event::Frame(frame))) = d.consume(&bytes).unwrap() else {
        panic!("missing frame");
    };
    assert_eq!(frame.tag(), &[0xff; 16]); // Unverified bytes are preserved.
}
