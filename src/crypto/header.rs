use std::{
    io::{self, Read},
    ops::RangeInclusive,
};

use super::CryptoError;
use crate::keys;

pub const VERSION: u8 = 1;
const MAGIC: [u8; 4] = *b"ENCR";
const CIPHER_AES_256_GCM: u8 = 1;

pub const SALT_LEN: usize = 32;
pub const NONCE_PREFIX_LEN: usize = 7;
pub const HEADER_LEN: usize = 4 + 1 + 1 + 1 + 1 + 4 + 4 + 4 + 4 + SALT_LEN + NONCE_PREFIX_LEN;

const DEFAULT_CHUNK_SIZE: u32 = 1 << 20;
const CHUNK_SIZE_RANGE: RangeInclusive<u32> = 64..=(64 << 20);

// Caps stop a crafted header from forcing excessive memory or CPU use during key derivation.
const MAX_ARGON2_M_COST_KIB: u32 = 4 << 20;
const MAX_ARGON2_T_COST: u32 = 64;
const MAX_ARGON2_P_COST: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    /// A single file, stored verbatim.
    File,
    /// A directory, stored as a zstd-compressed tarball.
    Archive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    /// The secret is a 256-bit key from `generate-key`.
    RawKey,
    /// The secret is a passphrase, stretched with Argon2id.
    Argon2id {
        m_cost_kib: u32,
        t_cost: u32,
        p_cost: u32,
    },
}

impl Kdf {
    pub const ARGON2ID: Self = Self::Argon2id {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    };
}

/// Fixed-size file header. Its encoded bytes are the AAD of every chunk, so any
/// modification to it fails authentication.
///
/// Layout (integers little-endian):
/// `magic[4] version cipher payload kdf m_cost:u32 t_cost:u32 p_cost:u32 chunk_size:u32 salt[32] nonce_prefix[7]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub payload: PayloadKind,
    pub kdf: Kdf,
    pub chunk_size: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl Header {
    pub fn generate(payload: PayloadKind, kdf: Kdf) -> Result<Self, CryptoError> {
        Self::with_chunk_size(payload, kdf, DEFAULT_CHUNK_SIZE)
    }

    pub(super) fn with_chunk_size(
        payload: PayloadKind,
        kdf: Kdf,
        chunk_size: u32,
    ) -> Result<Self, CryptoError> {
        let mut salt = [0; SALT_LEN];
        let mut nonce_prefix = [0; NONCE_PREFIX_LEN];
        keys::fill_random(&mut salt)?;
        keys::fill_random(&mut nonce_prefix)?;
        Ok(Self {
            payload,
            kdf,
            chunk_size,
            salt,
            nonce_prefix,
        })
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let payload: u8 = match self.payload {
            PayloadKind::File => 0,
            PayloadKind::Archive => 1,
        };
        let (kdf, m_cost, t_cost, p_cost) = match self.kdf {
            Kdf::RawKey => (0u8, 0u32, 0u32, 0u32),
            Kdf::Argon2id {
                m_cost_kib,
                t_cost,
                p_cost,
            } => (1, m_cost_kib, t_cost, p_cost),
        };
        let fields: [&[u8]; 11] = [
            &MAGIC,
            &[VERSION],
            &[CIPHER_AES_256_GCM],
            &[payload],
            &[kdf],
            &m_cost.to_le_bytes(),
            &t_cost.to_le_bytes(),
            &p_cost.to_le_bytes(),
            &self.chunk_size.to_le_bytes(),
            &self.salt,
            &self.nonce_prefix,
        ];

        let mut out = [0; HEADER_LEN];
        let mut pos = 0;
        for field in fields {
            out[pos..pos + field.len()].copy_from_slice(field);
            pos += field.len();
        }
        out
    }

    pub fn decode(bytes: &[u8; HEADER_LEN]) -> Result<Self, CryptoError> {
        let mut fields = Fields(bytes);

        if fields.take::<4>()? != MAGIC {
            return Err(CryptoError::NotEncrypted);
        }
        let [version] = fields.take()?;
        if version != VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }
        let [cipher] = fields.take()?;
        if cipher != CIPHER_AES_256_GCM {
            return Err(CryptoError::BadHeader("unknown cipher"));
        }
        let payload = match fields.take()? {
            [0] => PayloadKind::File,
            [1] => PayloadKind::Archive,
            _ => return Err(CryptoError::BadHeader("unknown payload type")),
        };
        let [kdf] = fields.take()?;
        let (m_cost, t_cost, p_cost) = (fields.u32()?, fields.u32()?, fields.u32()?);
        let kdf = match (kdf, m_cost, t_cost, p_cost) {
            (0, 0, 0, 0) => Kdf::RawKey,
            (1, m, t, p)
                if m <= MAX_ARGON2_M_COST_KIB
                    && (1..=MAX_ARGON2_T_COST).contains(&t)
                    && (1..=MAX_ARGON2_P_COST).contains(&p) =>
            {
                Kdf::Argon2id {
                    m_cost_kib: m,
                    t_cost: t,
                    p_cost: p,
                }
            }
            _ => return Err(CryptoError::BadHeader("invalid key derivation parameters")),
        };
        let chunk_size = fields.u32()?;
        if !CHUNK_SIZE_RANGE.contains(&chunk_size) {
            return Err(CryptoError::BadHeader("invalid chunk size"));
        }

        Ok(Self {
            payload,
            kdf,
            chunk_size,
            salt: fields.take()?,
            nonce_prefix: fields.take()?,
        })
    }

    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, CryptoError> {
        let mut bytes = [0; HEADER_LEN];
        reader
            .read_exact(&mut bytes)
            .map_err(|err| match err.kind() {
                io::ErrorKind::UnexpectedEof => CryptoError::NotEncrypted,
                _ => CryptoError::Io(err),
            })?;
        Self::decode(&bytes)
    }
}

struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], CryptoError> {
        let bytes: &'a [u8] = self.0;
        let (head, rest) = bytes
            .split_first_chunk::<N>()
            .ok_or(CryptoError::Truncated)?;
        self.0 = rest;
        Ok(*head)
    }

    fn u32(&mut self) -> Result<u32, CryptoError> {
        self.take().map(u32::from_le_bytes)
    }
}
