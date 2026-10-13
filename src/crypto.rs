//! Authenticated streaming encryption: AES-256-GCM in the STREAM construction.
//!
//! Memory use is bounded by one chunk regardless of input size, and every chunk is
//! authenticated before any of its plaintext is released.

mod header;
mod kdf;
mod stream;

use std::io::{self, BufRead, Read, Write};

use rand::rngs::SysError;

use crate::keys::Secret;

pub use header::{Header, PayloadKind};
pub use stream::{DecryptReader, EncryptWriter};

use header::Kdf;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("not an encr file")]
    NotEncrypted,
    #[error("unsupported format version {0}; a newer encr is required")]
    UnsupportedVersion(u8),
    #[error("corrupted header: {0}")]
    BadHeader(&'static str),
    #[error("the file is truncated")]
    Truncated,
    #[error("this file was encrypted with a generated key, but the supplied key is not one")]
    ExpectedRawKey,
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("decryption failed: wrong key, or the file is corrupted")]
    WrongKeyOrCorrupted,
    #[error("decryption failed at chunk {0}: the file is corrupted or has been tampered with")]
    Tampered(u32),
    #[error("encryption failed")]
    Cipher,
    #[error("input exceeds the maximum stream length")]
    StreamTooLong,
    #[error("secure random number generator failed: {0}")]
    Rng(#[from] SysError),
    #[error(transparent)]
    Io(io::Error),
}

impl From<io::Error> for CryptoError {
    fn from(err: io::Error) -> Self {
        // Stream adapters must speak io::Error; unwrap our own errors on the way back out.
        err.downcast::<Self>().unwrap_or_else(Self::Io)
    }
}

impl From<CryptoError> for io::Error {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::Io(err) => err,
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        }
    }
}

/// Writes a fresh header to `sink` and returns a writer that encrypts everything written to it.
/// Call [`EncryptWriter::finish`] to seal the stream.
pub fn encryptor<W: Write>(
    sink: W,
    payload: PayloadKind,
    secret: &Secret,
) -> Result<EncryptWriter<W>, CryptoError> {
    let kdf = if secret.as_raw_key().is_some() {
        Kdf::RawKey
    } else {
        Kdf::ARGON2ID
    };
    let header = Header::generate(payload, kdf)?;
    let key = kdf::file_key(secret, &header)?;
    EncryptWriter::new(sink, &header, &key)
}

/// Parses the header from `source` and returns a reader yielding authenticated plaintext.
pub fn decryptor<R: Read>(
    mut source: R,
    secret: &Secret,
) -> Result<(Header, DecryptReader<R>), CryptoError> {
    let header = Header::read_from(&mut source)?;
    let key = kdf::file_key(secret, &header)?;
    let mut reader = DecryptReader::new(source, &header, &key);
    // Authenticate the first chunk now, so a wrong key fails before any output is created.
    reader.fill_buf()?;
    Ok((header, reader))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;

    const CHUNK: u32 = 64;

    fn raw_secret() -> Secret {
        Secret::new(keys::generate_key().unwrap().to_string()).unwrap()
    }

    fn seal(plaintext: &[u8], secret: &Secret, kdf: Kdf) -> Vec<u8> {
        let header = Header::with_chunk_size(PayloadKind::File, kdf, CHUNK).unwrap();
        let key = kdf::file_key(secret, &header).unwrap();
        let mut writer = EncryptWriter::new(Vec::new(), &header, &key).unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap()
    }

    fn open(ciphertext: &[u8], secret: &Secret) -> io::Result<Vec<u8>> {
        let (_, mut reader) = decryptor(ciphertext, secret)?;
        let mut plaintext = Vec::new();
        reader.read_to_end(&mut plaintext)?;
        reader.finish()?;
        Ok(plaintext)
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn round_trips_across_chunk_boundaries() {
        let secret = raw_secret();
        for len in [0, 1, 63, 64, 65, 128, 129, 1000] {
            let plaintext = sample(len);
            let sealed = seal(&plaintext, &secret, Kdf::RawKey);
            assert_eq!(open(&sealed, &secret).unwrap(), plaintext, "length {len}");
        }
    }

    #[test]
    fn round_trips_with_passphrase() {
        let secret = Secret::new("a long enough passphrase".into()).unwrap();
        let cheap = Kdf::Argon2id {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        };
        let plaintext = sample(300);
        let sealed = seal(&plaintext, &secret, cheap);
        assert_eq!(open(&sealed, &secret).unwrap(), plaintext);
    }

    #[test]
    fn wrong_key_fails_up_front() {
        let sealed = seal(&sample(500), &raw_secret(), Kdf::RawKey);
        let result = decryptor(sealed.as_slice(), &raw_secret());
        assert!(matches!(result, Err(CryptoError::WrongKeyOrCorrupted)));
    }

    #[test]
    fn raw_key_file_rejects_passphrase() {
        let sealed = seal(&sample(10), &raw_secret(), Kdf::RawKey);
        let passphrase = Secret::new("not a key".into()).unwrap();
        let result = decryptor(sealed.as_slice(), &passphrase);
        assert!(matches!(result, Err(CryptoError::ExpectedRawKey)));
    }

    #[test]
    fn any_flipped_bit_is_detected() {
        let secret = raw_secret();
        let sealed = seal(&sample(150), &secret, Kdf::RawKey);
        for i in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[i] ^= 0x01;
            assert!(
                open(&tampered, &secret).is_err(),
                "flip at byte {i} went unnoticed"
            );
        }
    }

    #[test]
    fn truncation_is_detected() {
        let secret = raw_secret();
        let sealed = seal(&sample(128), &secret, Kdf::RawKey);
        let one_chunk = header::HEADER_LEN + CHUNK as usize + stream::TAG_LEN;
        assert!(open(&sealed[..one_chunk], &secret).is_err());
        assert!(open(&sealed[..sealed.len() - 1], &secret).is_err());
        assert!(open(&sealed[..header::HEADER_LEN], &secret).is_err());
    }

    #[test]
    fn reordered_chunks_are_detected() {
        let secret = raw_secret();
        let sealed = seal(&sample(200), &secret, Kdf::RawKey);
        let start = header::HEADER_LEN;
        let len = CHUNK as usize + stream::TAG_LEN;
        let mut swapped = sealed.clone();
        swapped[start..start + len].copy_from_slice(&sealed[start + len..start + 2 * len]);
        swapped[start + len..start + 2 * len].copy_from_slice(&sealed[start..start + len]);
        assert!(open(&swapped, &secret).is_err());
    }

    #[test]
    fn header_round_trips() {
        let header = Header::generate(PayloadKind::Archive, Kdf::ARGON2ID).unwrap();
        assert_eq!(Header::decode(&header.encode()).unwrap(), header);
    }
}
