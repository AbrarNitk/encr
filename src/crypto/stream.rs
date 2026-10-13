use std::io::{self, BufRead, Read, Write};

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInOut, KeyInit, Nonce, Tag},
};

use super::{
    CryptoError,
    header::{HEADER_LEN, Header, NONCE_PREFIX_LEN},
};
use crate::keys::KEY_LEN;

pub const TAG_LEN: usize = 16;

/// STREAM nonce schedule (Hoang et al.): `prefix[7] ‖ counter:u32be ‖ last_flag`.
/// The counter defeats reordering; the last-chunk flag makes truncation at a chunk
/// boundary detectable.
struct ChunkCipher {
    cipher: Aes256Gcm,
    aad: [u8; HEADER_LEN],
    prefix: [u8; NONCE_PREFIX_LEN],
    counter: u32,
}

impl ChunkCipher {
    fn new(header: &Header, key: &[u8; KEY_LEN]) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
            aad: header.encode(),
            prefix: header.nonce_prefix,
            counter: 0,
        }
    }

    fn nonce(&self, last: bool) -> Nonce<Aes256Gcm> {
        let mut nonce = [0; 12];
        nonce[..NONCE_PREFIX_LEN].copy_from_slice(&self.prefix);
        nonce[NONCE_PREFIX_LEN..11].copy_from_slice(&self.counter.to_be_bytes());
        nonce[11] = u8::from(last);
        nonce.into()
    }

    fn advance(&mut self) -> io::Result<()> {
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(CryptoError::StreamTooLong)?;
        Ok(())
    }
}

/// Buffers plaintext into fixed-size chunks and encrypts each one in place.
pub struct EncryptWriter<W: Write> {
    inner: W,
    chunks: ChunkCipher,
    buf: Vec<u8>,
    chunk_size: usize,
}

impl<W: Write> EncryptWriter<W> {
    pub(super) fn new(
        mut inner: W,
        header: &Header,
        key: &[u8; KEY_LEN],
    ) -> Result<Self, CryptoError> {
        let chunks = ChunkCipher::new(header, key);
        inner.write_all(&chunks.aad)?;
        let chunk_size = header.chunk_size as usize;
        Ok(Self {
            inner,
            chunks,
            buf: Vec::with_capacity(chunk_size + TAG_LEN),
            chunk_size,
        })
    }

    /// Seals the final chunk. A stream dropped without `finish` is rejected on decryption.
    pub fn finish(mut self) -> io::Result<W> {
        self.seal(true)?;
        self.inner.flush()?;
        Ok(self.inner)
    }

    fn seal(&mut self, last: bool) -> io::Result<()> {
        let nonce = self.chunks.nonce(last);
        let tag = self
            .chunks
            .cipher
            .encrypt_inout_detached(&nonce, &self.chunks.aad, self.buf.as_mut_slice().into())
            .map_err(|_| CryptoError::Cipher)?;
        self.buf.extend_from_slice(&tag);
        self.inner.write_all(&self.buf)?;
        self.buf.clear();
        if !last {
            self.chunks.advance()?;
        }
        Ok(())
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        // A full chunk is only sealed once more data arrives, since the last chunk
        // must carry the final flag.
        if self.buf.len() == self.chunk_size {
            self.seal(false)?;
        }
        let n = data.len().min(self.chunk_size - self.buf.len());
        self.buf.extend_from_slice(&data[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Streaming,
    Done,
    Failed,
}

/// Decrypts chunk by chunk. Plaintext is only exposed after its chunk authenticates.
pub struct DecryptReader<R: Read> {
    inner: R,
    chunks: ChunkCipher,
    /// One full ciphertext chunk plus one byte of lookahead.
    buf: Vec<u8>,
    pos: usize,
    end: usize,
    carry: Option<u8>,
    state: State,
}

impl<R: Read> DecryptReader<R> {
    pub(super) fn new(inner: R, header: &Header, key: &[u8; KEY_LEN]) -> Self {
        let ciphertext_chunk = header.chunk_size as usize + TAG_LEN;
        Self {
            inner,
            chunks: ChunkCipher::new(header, key),
            buf: vec![0; ciphertext_chunk + 1],
            pos: 0,
            end: 0,
            carry: None,
            state: State::Streaming,
        }
    }

    /// Consumes and authenticates whatever remains, so truncation is caught even when
    /// the consumer (e.g. a tar parser) stops reading early.
    pub fn finish(mut self) -> io::Result<()> {
        loop {
            let available = self.fill_buf()?.len();
            if available == 0 {
                return Ok(());
            }
            self.consume(available);
        }
    }

    fn open_next(&mut self) -> io::Result<()> {
        let ciphertext_chunk = self.buf.len() - 1;
        let mut filled = 0;
        if let Some(byte) = self.carry.take() {
            self.buf[0] = byte;
            filled = 1;
        }
        // Reading one byte past a full chunk reveals whether this chunk is the last.
        filled += read_full(&mut self.inner, &mut self.buf[filled..])?;
        let last = filled <= ciphertext_chunk;
        if !last {
            self.carry = Some(self.buf[ciphertext_chunk]);
            filled = ciphertext_chunk;
        }

        let counter = self.chunks.counter;
        let body_len = filled.checked_sub(TAG_LEN).ok_or(CryptoError::Truncated)?;
        let (body, tag) = self.buf[..filled].split_at_mut(body_len);
        let tag = Tag::<Aes256Gcm>::try_from(&*tag).map_err(|_| auth_error(counter))?;
        let nonce = self.chunks.nonce(last);
        self.chunks
            .cipher
            .decrypt_inout_detached(&nonce, &self.chunks.aad, body.into(), &tag)
            .map_err(|_| auth_error(counter))?;

        self.pos = 0;
        self.end = body_len;
        if last {
            self.state = State::Done;
        } else {
            self.chunks.advance()?;
        }
        Ok(())
    }
}

impl<R: Read> BufRead for DecryptReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        while self.pos == self.end {
            match self.state {
                State::Done => break,
                State::Failed => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "encrypted stream previously failed verification",
                    ));
                }
                State::Streaming => {
                    if let Err(err) = self.open_next() {
                        self.state = State::Failed;
                        return Err(err);
                    }
                }
            }
        }
        Ok(&self.buf[self.pos..self.end])
    }

    fn consume(&mut self, amount: usize) {
        self.pos = (self.pos + amount).min(self.end);
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let n = available.len().min(out.len());
        out[..n].copy_from_slice(&available[..n]);
        self.consume(n);
        Ok(n)
    }
}

fn auth_error(chunk: u32) -> CryptoError {
    if chunk == 0 {
        CryptoError::WrongKeyOrCorrupted
    } else {
        CryptoError::Tampered(chunk)
    }
}

/// Like `read_exact`, but returns the byte count at EOF instead of failing.
fn read_full<R: Read>(reader: &mut R, mut buf: &mut [u8]) -> io::Result<usize> {
    let requested = buf.len();
    while !buf.is_empty() {
        match reader.read(buf) {
            Ok(0) => break,
            Ok(n) => buf = &mut std::mem::take(&mut buf)[n..],
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(requested - buf.len())
}
