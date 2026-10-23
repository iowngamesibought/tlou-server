//! The game's legacy framed-service transport (a keyed stream cipher with a
//! per-frame tag), not a platform identity verifier: possession of the
//! title's shared key proves nothing about who is connecting.

use crate::codec::{Decoder, Event, Hello, HelloReply, OpaqueFrame};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Structure(crate::codec::Error),
    TrailingBytes,
    TagMismatch,
    TooLarge,
    Closed,
    WrongState,
    UnsupportedService,
    EmptyTicket,
    TicketRejected(VerifyError),
    InvalidIdentity,
}

// Independent expression of the wire-contract state transition; the caller
// supplies the key. Never embed the title's key or log intermediate states.
struct Mixer([u32; 4]);

impl Mixer {
    fn step(&mut self, word: u32, decrypt: bool) -> u32 {
        let [a, b, c, d] = self.0;
        let d = d ^ 0x5b3a_a654;
        let c = c.wrapping_add(a).wrapping_add(d).rotate_left(7);
        let b = b.wrapping_add(d).wrapping_add(c).rotate_left(11);
        let c = c ^ 0x7597_0a4d;
        let a = a.wrapping_add(c).wrapping_add(b).rotate_left(17);
        let mixed = d.wrapping_add((a & b) | (c & !b)) ^ word;
        self.0 = [!a, !b, c, if decrypt { word } else { mixed }];
        mixed
    }

    fn schedule(key: &[u8; 16], counter: u32) -> Self {
        let mut state = Self(std::array::from_fn(|i| {
            u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap())
        }));
        state.step(counter, false);
        for word in state.0 {
            state.step(word, false);
        }
        state
    }

    fn tag(mut self, padded: &[u8]) -> [u8; 16] {
        for word in padded.as_chunks::<4>().0 {
            self.step(u32::from_le_bytes(*word), false);
        }
        let xor = self.0.iter().fold(0, |acc, word| acc ^ word);
        let mut tag = [0; 16];
        for (bytes, word) in tag.as_chunks_mut::<4>().0.iter_mut().zip(self.0) {
            bytes.copy_from_slice(&(xor ^ word).to_le_bytes());
        }
        tag
    }

    fn transform(mut self, data: &[u8], decrypt: bool) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        for word in data.as_chunks::<4>().0 {
            result.extend_from_slice(&self.step(u32::from_le_bytes(*word), decrypt).to_le_bytes());
        }
        result
    }
}

/// An ordered, bounded direction of the legacy transport.
///
/// This is not modern authenticated encryption: the header is not included in
/// the tag, and directions/sessions with equal counters share the same cipher
/// state. Valid transport tags never establish account identity.
/// No Clone/Debug is provided, to avoid accidental state copies/key logging.
pub struct Channel {
    key: [u8; 16],
    counter: u32,
    max_frame_len: usize,
    closed: bool,
}

impl Channel {
    pub fn new(key: [u8; 16], counter: u32, max_frame_len: usize) -> Result<Self, Error> {
        Decoder::frames(max_frame_len).map_err(Error::Structure)?;
        Ok(Self {
            key,
            counter,
            max_frame_len,
            closed: false,
        })
    }

    pub fn counter(&self) -> u32 {
        self.counter
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Seal one complete frame. Counter advances only after successful output.
    /// An output error also closes the direction; retry with a new session.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        let result = self.seal_inner(plaintext);
        self.finish_operation(result)
    }

    fn seal_inner(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let len = u16::try_from(plaintext.len()).map_err(|_| Error::TooLarge)?;
        let padded_len = (plaintext.len() + 3) & !3;
        if 20 + padded_len > self.max_frame_len {
            return Err(Error::TooLarge);
        }
        let mut padded = plaintext.to_vec();
        padded.resize(padded_len, 0);
        let tag = Mixer::schedule(&self.key, self.counter).tag(&padded);
        let body = Mixer::schedule(&self.key, self.counter).transform(&padded, false);
        Ok(OpaqueFrame::new(len, tag, body)
            .map_err(Error::Structure)?
            .encode())
    }

    /// Open exactly one frame, exposing plaintext only after tag validation.
    /// A socket adapter must frame its input first; partial/coalesced inputs
    /// belong in tlou-ticket-codec::Decoder, not repeated calls to this method.
    pub fn open(&mut self, wire: &[u8]) -> Result<Vec<u8>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        let result = self.open_inner(wire);
        self.finish_operation(result)
    }

    fn open_inner(&self, wire: &[u8]) -> Result<Vec<u8>, Error> {
        let mut decoder = Decoder::frames(self.max_frame_len).map_err(Error::Structure)?;
        let (used, event) = decoder.consume(wire).map_err(Error::Structure)?;
        if used != wire.len() {
            return Err(Error::TrailingBytes);
        }
        let frame = match event {
            Some(Event::Frame(frame)) => frame,
            _ => return Err(Error::Structure(crate::codec::Error::Truncated)),
        };
        let mut plaintext =
            Mixer::schedule(&self.key, self.counter).transform(frame.ciphertext(), true);
        let calculated = Mixer::schedule(&self.key, self.counter).tag(&plaintext);
        // Fixed-work comparison with no byte-position early exit. This is not
        // a compiler/hardware-level constant-time guarantee.
        let mismatch = calculated
            .iter()
            .zip(frame.tag())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if mismatch != 0 {
            return Err(Error::TagMismatch);
        }
        // The tag covers the padding too. Retail clients leave stale
        // bytes there (observed 2026-10-22, report-server), so it is
        // authenticated but not required to be zero.
        plaintext.truncate(usize::from(frame.plaintext_len()));
        Ok(plaintext)
    }

    fn finish_operation<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_ok() {
            self.counter = self.counter.wrapping_add(1);
        } else {
            self.close();
        }
        result
    }
}

/// Direction mapping after hello, independent of identity/auth status.
pub struct ServerTransport {
    pub receive: Channel,
    pub send: Channel,
}

impl ServerTransport {
    pub fn new(
        key: [u8; 16],
        client_nonce: u32,
        server_seed: u32,
        max_frame_len: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            receive: Channel::new(key, server_seed, max_frame_len)?,
            send: Channel::new(key, client_nonce, max_frame_len)?,
        })
    }

    pub fn close(&mut self) {
        self.receive.close();
        self.send.close();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    Unavailable,
    Malformed,
    UntrustedIssuer,
    Signature,
    Expired,
    WrongService,
    Replay,
}

/// Trusted verifier output, never extracted by searching ticket strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub authority: String,
    pub subject: String,
}

pub struct VerifyContext {
    pub now_unix_seconds: u64,
}

/// An implementation must validate format, issuer/signature, service binding,
/// time bounds, identity and cross-session replay policy before returning Ok.
/// No such platform verifier is shipped in this increment.
pub trait TicketVerifier {
    fn verify(&mut self, ticket: &[u8], context: &VerifyContext) -> Result<Identity, VerifyError>;
}

#[derive(Default)]
pub struct DenyAll;

impl TicketVerifier for DenyAll {
    fn verify(&mut self, _: &[u8], _: &VerifyContext) -> Result<Identity, VerifyError> {
        Err(VerifyError::Unavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    AwaitTicket,
    Authenticated,
    Rejected,
    Closed,
}

/// One ticket attempt after a parsed ticket-server hello.
/// An identity result is an internal decision, never a fabricated game reply.
pub struct AuthSession<V = DenyAll> {
    transport: ServerTransport,
    verifier: V,
    state: AuthState,
    identity: Option<Identity>,
}

impl AuthSession<DenyAll> {
    pub fn new(
        hello: &Hello,
        key: [u8; 16],
        server_seed: u32,
        max_frame_len: usize,
    ) -> Result<(Self, HelloReply), Error> {
        Self::with_verifier(hello, key, server_seed, max_frame_len, DenyAll)
    }
}

impl<V: TicketVerifier> AuthSession<V> {
    /// Explicit trusted adapter injection. Tests may use a synthetic verifier;
    /// that does not validate any real platform ticket.
    pub fn with_verifier(
        hello: &Hello,
        key: [u8; 16],
        server_seed: u32,
        max_frame_len: usize,
        verifier: V,
    ) -> Result<(Self, HelloReply), Error> {
        if hello.service != "ticket-server" {
            return Err(Error::UnsupportedService);
        }
        Ok((
            Self {
                transport: ServerTransport::new(
                    key,
                    hello.client_nonce,
                    server_seed,
                    max_frame_len,
                )?,
                verifier,
                state: AuthState::AwaitTicket,
                identity: None,
            },
            HelloReply {
                server_choice: [0; 3],
                token: server_seed,
            },
        ))
    }

    pub fn state(&self) -> AuthState {
        self.state
    }

    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    pub fn close(&mut self) {
        self.transport.close();
        self.identity = None;
        self.state = AuthState::Closed;
    }

    /// Seal the server's ticket response. Only available after the injected
    /// verifier accepted the ticket, so a deny-default session can never emit
    /// a success-shaped reply.
    pub fn seal_reply(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        if self.state != AuthState::Authenticated {
            return Err(Error::WrongState);
        }
        self.transport.send.seal(plaintext)
    }

    pub fn submit(&mut self, wire: &[u8], now_unix_seconds: u64) -> Result<(), Error> {
        if self.state != AuthState::AwaitTicket {
            self.close();
            return Err(Error::WrongState);
        }
        let result = self.verify_once(wire, now_unix_seconds);
        match result {
            Ok(identity) => {
                self.identity = Some(identity);
                self.state = AuthState::Authenticated;
                Ok(())
            }
            Err(error) => {
                self.transport.close();
                self.state = AuthState::Rejected;
                Err(error)
            }
        }
    }

    fn verify_once(&mut self, wire: &[u8], now_unix_seconds: u64) -> Result<Identity, Error> {
        let ticket = self.transport.receive.open(wire)?;
        if ticket.is_empty() {
            return Err(Error::EmptyTicket);
        }
        let identity = self
            .verifier
            .verify(&ticket, &VerifyContext { now_unix_seconds })
            .map_err(Error::TicketRejected)?;
        if identity.authority.is_empty() || identity.subject.is_empty() {
            return Err(Error::InvalidIdentity);
        }
        Ok(identity)
    }
}
