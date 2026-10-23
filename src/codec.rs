//! Structural decoding only: successful framing is NEVER authentication.
//! No socket, cryptographic primitive, ticket validation, or gameplay behavior.
//! Layouts are deliberately strict: any deviation is a structural error.

pub const HELLO_LEN: usize = 88;
pub const REPLY_LEN: usize = 8;
pub const HEADER_LEN: usize = 20;
pub const MAX_FRAME_LEN: usize = HEADER_LEN + 65536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidLimit,
    InvalidMagic,
    MissingServiceTerminator,
    NonAsciiService,
    InvalidPadding,
    FrameTooLarge,
    InvalidCiphertextLength,
    Truncated,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub client_nonce: u32,
    pub service: String,
}

impl Hello {
    /// Ignore reserved bytes, sender residue and bytes following the first NUL.
    /// Do not log the raw hello: those regions may disclose client memory.
    pub fn parse(bytes: &[u8; HELLO_LEN]) -> Result<Self, Error> {
        if bytes[0] != 0x11 {
            return Err(Error::InvalidMagic);
        }
        let name = &bytes[24..88];
        let end = name
            .iter()
            .position(|b| *b == 0)
            .ok_or(Error::MissingServiceTerminator)?;
        if !name[..end].is_ascii() {
            return Err(Error::NonAsciiService);
        }
        Ok(Self {
            client_nonce: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            service: String::from_utf8(name[..end].to_vec()).unwrap(),
        })
    }
}

/// Hello reply framing only. `token` is a caller-supplied counter seed,
/// NOT an authenticated session, authorization decision or user identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloReply {
    pub server_choice: [u8; 3],
    pub token: u32,
}

impl HelloReply {
    pub fn parse(bytes: &[u8; REPLY_LEN]) -> Result<Self, Error> {
        if bytes[0] != 0x22 {
            return Err(Error::InvalidMagic);
        }
        Ok(Self {
            server_choice: bytes[1..4].try_into().unwrap(),
            token: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
        })
    }

    pub fn encode(&self) -> [u8; REPLY_LEN] {
        let mut bytes = [0; REPLY_LEN];
        bytes[0] = 0x22;
        bytes[1..4].copy_from_slice(&self.server_choice);
        bytes[4..8].copy_from_slice(&self.token.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueFrame {
    plaintext_len: u16,
    tag: [u8; 16],
    ciphertext: Vec<u8>,
}

impl OpaqueFrame {
    /// Wrap bytes from an external crypto adapter; does not verify the tag.
    pub fn new(plaintext_len: u16, tag: [u8; 16], ciphertext: Vec<u8>) -> Result<Self, Error> {
        if ciphertext.len() != body_len(plaintext_len) {
            return Err(Error::InvalidCiphertextLength);
        }
        Ok(Self {
            plaintext_len,
            tag,
            ciphertext,
        })
    }

    pub fn plaintext_len(&self) -> u16 {
        self.plaintext_len
    }
    pub fn tag(&self) -> &[u8; 16] {
        &self.tag
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LEN + self.ciphertext.len());
        bytes.extend_from_slice(&[0x33, padding(self.plaintext_len)]);
        bytes.extend_from_slice(&self.plaintext_len.to_be_bytes());
        bytes.extend_from_slice(&self.tag);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }
}

fn padding(len: u16) -> u8 {
    ((4 - usize::from(len) % 4) % 4) as u8
}
fn body_len(len: u16) -> usize {
    usize::from(len) + usize::from(padding(len))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Hello(Hello),
    Frame(OpaqueFrame),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Hello,
    Header,
    Body,
    Closed,
}

/// One event per `consume` call, so a coalesced input cannot cause an unbounded
/// output queue. The caller must advance by the returned consumed byte count
/// and call again with the remainder. Empty input never advances the state.
/// At most max_frame_len bytes are retained. No network timers are provided.
pub struct Decoder {
    phase: Phase,
    buffer: Vec<u8>,
    target: usize,
    max_frame_len: usize,
}

impl Decoder {
    /// Start at the client hello. This is a byte-order state machine, not a
    /// handshake/authentication state machine; the caller owns reply timing.
    pub fn client_stream(max_frame_len: usize) -> Result<Self, Error> {
        Self::new(Phase::Hello, HELLO_LEN, max_frame_len)
    }

    /// Start after the hello exchange (either direction).
    pub fn frames(max_frame_len: usize) -> Result<Self, Error> {
        Self::new(Phase::Header, HEADER_LEN, max_frame_len)
    }

    fn new(phase: Phase, target: usize, max_frame_len: usize) -> Result<Self, Error> {
        if !(HELLO_LEN..=MAX_FRAME_LEN).contains(&max_frame_len) {
            return Err(Error::InvalidLimit);
        }
        Ok(Self {
            phase,
            buffer: Vec::with_capacity(max_frame_len),
            target,
            max_frame_len,
        })
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Any parse error closes this decoder permanently. Discard the connection
    /// rather than trying to resynchronize by searching for a magic byte.
    pub fn consume(&mut self, input: &[u8]) -> Result<(usize, Option<Event>), Error> {
        if self.phase == Phase::Closed {
            return Err(Error::Closed);
        }
        let result = self.consume_inner(input);
        if result.is_err() {
            self.phase = Phase::Closed;
            self.buffer.clear();
        }
        result
    }

    fn consume_inner(&mut self, input: &[u8]) -> Result<(usize, Option<Event>), Error> {
        let mut used = 0;
        loop {
            let take = (self.target - self.buffer.len()).min(input.len() - used);
            self.buffer.extend_from_slice(&input[used..used + take]);
            used += take;
            if self.buffer.len() < self.target {
                return Ok((used, None));
            }

            match self.phase {
                Phase::Hello => {
                    let hello = Hello::parse(self.buffer.as_slice().try_into().unwrap())?;
                    self.buffer.clear();
                    self.phase = Phase::Header;
                    self.target = HEADER_LEN;
                    return Ok((used, Some(Event::Hello(hello))));
                }
                Phase::Header => {
                    if self.buffer[0] != 0x33 {
                        return Err(Error::InvalidMagic);
                    }
                    let len = u16::from_be_bytes([self.buffer[2], self.buffer[3]]);
                    if self.buffer[1] != padding(len) {
                        return Err(Error::InvalidPadding);
                    }
                    self.target = HEADER_LEN + body_len(len);
                    if self.target > self.max_frame_len {
                        return Err(Error::FrameTooLarge);
                    }
                    self.phase = Phase::Body;
                }
                Phase::Body => {
                    let frame = OpaqueFrame::new(
                        u16::from_be_bytes([self.buffer[2], self.buffer[3]]),
                        self.buffer[4..20].try_into().unwrap(),
                        self.buffer[20..].to_vec(),
                    )?;
                    self.buffer.clear();
                    self.phase = Phase::Header;
                    self.target = HEADER_LEN;
                    return Ok((used, Some(Event::Frame(frame))));
                }
                Phase::Closed => unreachable!(),
            }
        }
    }

    /// EOF at a frame boundary is clean; EOF during a hello/header/body is
    /// truncated. Even clean EOF closes the decoder to prevent accidental reuse.
    pub fn finish(&mut self) -> Result<(), Error> {
        if self.phase == Phase::Closed {
            return Err(Error::Closed);
        }
        let clean = self.phase == Phase::Header && self.buffer.is_empty();
        self.phase = Phase::Closed;
        self.buffer.clear();
        if clean { Ok(()) } else { Err(Error::Truncated) }
    }
}
