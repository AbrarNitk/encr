use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{
    CryptoError,
    header::{Header, Kdf},
};
use crate::keys::{KEY_LEN, Secret, SecretKey};

const FILE_KEY_INFO: &[u8] = b"encr v1 aes-256-gcm file key";

/// Derives the per-file AES key. Mixing the random header salt in through HKDF gives
/// every file a unique key, so nonces never repeat even when one secret encrypts many files.
pub fn file_key(secret: &Secret, header: &Header) -> Result<SecretKey, CryptoError> {
    let master = match header.kdf {
        Kdf::RawKey => secret.as_raw_key().ok_or(CryptoError::ExpectedRawKey)?,
        Kdf::Argon2id {
            m_cost_kib,
            t_cost,
            p_cost,
        } => {
            let params = Params::new(m_cost_kib, t_cost, p_cost, Some(KEY_LEN))
                .map_err(|err| CryptoError::Kdf(err.to_string()))?;
            let mut stretched: SecretKey = Zeroizing::new([0; KEY_LEN]);
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(secret.passphrase(), &header.salt, stretched.as_mut_slice())
                .map_err(|err| CryptoError::Kdf(err.to_string()))?;
            stretched
        }
    };

    let mut key: SecretKey = Zeroizing::new([0; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(&header.salt), master.as_slice())
        .expand(FILE_KEY_INFO, key.as_mut_slice())
        .map_err(|err| CryptoError::Kdf(err.to_string()))?;
    Ok(key)
}
