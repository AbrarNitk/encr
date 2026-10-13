use anyhow::ensure;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{
    Rng, RngExt, TryRng,
    rngs::{SysError, SysRng},
    seq::SliceRandom,
};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;

pub type SecretKey = Zeroizing<[u8; KEY_LEN]>;

/// Fills `buf` directly from the operating system's CSPRNG.
pub fn fill_random(buf: &mut [u8]) -> Result<(), SysError> {
    SysRng.try_fill_bytes(buf)
}

/// A fresh 256-bit key as unpadded URL-safe base64: 43 shell-safe characters.
pub fn generate_key() -> Result<Zeroizing<String>, SysError> {
    let mut key: SecretKey = Zeroizing::new([0; KEY_LEN]);
    fill_random(key.as_mut_slice())?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(key.as_slice())))
}

/// A user-supplied secret: either a key from [`generate_key`] or an arbitrary passphrase.
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: String) -> anyhow::Result<Self> {
        let value = Zeroizing::new(value);
        ensure!(!value.is_empty(), "the key must not be empty");
        Ok(Self(value))
    }

    /// Decodes the secret as a raw key, if it is one.
    pub fn as_raw_key(&self) -> Option<SecretKey> {
        let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(self.0.trim()).ok()?);
        if decoded.len() != KEY_LEN {
            return None;
        }
        let mut key: SecretKey = Zeroizing::new([0; KEY_LEN]);
        key.copy_from_slice(&decoded);
        Some(key)
    }

    pub fn passphrase(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn char_count(&self) -> usize {
        self.0.chars().count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Complexity {
    Weak,
    Medium,
    Strong,
}

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
// Quotes, backslash, backtick, pipe and space are left out so passwords paste safely into shells.
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}<>?,.:;~";

impl Complexity {
    fn classes(self) -> &'static [&'static [u8]] {
        match self {
            Self::Weak => &[LOWER, DIGITS],
            Self::Medium => &[LOWER, UPPER, DIGITS],
            Self::Strong => &[LOWER, UPPER, DIGITS, SYMBOLS],
        }
    }
}

pub fn generate_password(
    complexity: Complexity,
    length: usize,
) -> anyhow::Result<Zeroizing<String>> {
    let classes = complexity.classes();
    ensure!(
        length >= classes.len(),
        "password length must be at least {} for this level",
        classes.len()
    );

    let alphabet = classes.concat();
    let mut rng = rand::rng();
    let mut chars = Zeroizing::new(Vec::with_capacity(length));

    // Seed one character from every class so the requested complexity is guaranteed,
    // fill the rest uniformly, then shuffle to hide where the seeded characters sit.
    for class in classes {
        chars.push(pick(&mut rng, class));
    }
    while chars.len() < length {
        chars.push(pick(&mut rng, &alphabet));
    }
    chars.shuffle(&mut rng);

    let mut password = Zeroizing::new(String::with_capacity(length));
    password.extend(chars.iter().copied().map(char::from));
    Ok(password)
}

/// Uniform pick without modulo bias.
fn pick<R: Rng>(rng: &mut R, set: &[u8]) -> u8 {
    set[rng.random_range(0..set.len())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_is_recognised_as_raw() {
        let secret = Secret::new(generate_key().unwrap().to_string()).unwrap();
        assert!(secret.as_raw_key().is_some());
    }

    #[test]
    fn passphrase_is_not_raw() {
        let secret = Secret::new("correct horse battery staple".into()).unwrap();
        assert!(secret.as_raw_key().is_none());
    }

    #[test]
    fn empty_secret_is_rejected() {
        assert!(Secret::new(String::new()).is_err());
    }

    #[test]
    fn passwords_honour_length_and_classes() {
        for complexity in [Complexity::Weak, Complexity::Medium, Complexity::Strong] {
            let classes = complexity.classes();
            for length in [classes.len(), 8, 64] {
                let password = generate_password(complexity, length).unwrap();
                assert_eq!(password.len(), length);
                for class in classes {
                    assert!(password.bytes().any(|b| class.contains(&b)));
                }
                assert!(
                    password
                        .bytes()
                        .all(|b| classes.iter().any(|c| c.contains(&b)))
                );
            }
        }
    }

    #[test]
    fn too_short_password_is_rejected() {
        assert!(generate_password(Complexity::Strong, 3).is_err());
    }
}
