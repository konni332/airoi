use std::path::PathBuf;
use std::sync::Mutex;
use argon2::{Argon2, Params};
use base64::Engine;
use base64::engine::general_purpose;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use chacha20poly1305::aead::Aead;
use dirs::config_dir;
use rand::{TryRngCore};
use rand::rngs::OsRng;
use zeroize::{Zeroize};
use crate::error::AiroiError;
use crate::error::Result;
use crate::keys::KeyPair;
use crate::storage::serialize_keypair;

struct Passphrase {
    inner: Mutex<Option<String>>
}

impl Passphrase {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(None)
        }
    }
    pub fn set(&self, passphrase: String) {
        let mut inner = self.inner.lock().unwrap();
        *inner = Some(passphrase);
    }
    pub fn get(&self) -> Option<String> {
        let inner = self.inner.lock().unwrap();
        inner.clone()
    }
}

static SESSION_PASSPHRASE: Passphrase = Passphrase::new();

impl Drop for Passphrase {
    fn drop(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(ref mut s) = *inner {
            s.zeroize();
        }
        *inner = None;
    }
}
pub fn get_passphrase() -> String {
    SESSION_PASSPHRASE.get().unwrap_or_else(|| {
        let passphrase = rpassword::prompt_password("Enter passphrase: ").unwrap();
        SESSION_PASSPHRASE.set(passphrase.clone());
        passphrase
    })
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct EncryptedKeystore {
    salt_b64: String,
    nonce_b64: String,
    ct_b64: String,
    argon_m: u32,
    argon_t: u32,
    argon_p: u32,
}

fn keystore_path() -> Result<PathBuf> {
    let mut p = config_dir().ok_or_else(|| {
        return std::io::Error::new(std::io::ErrorKind::NotFound, "No config dir found")
    })?;
    p.push("airoi");
    std::fs::create_dir_all(&p)?;
    p.push("keys.enc");
    Ok(p)
}

fn derive_key(passphrase: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; 32]> {
    let params = Params::new(m, t, p, None)
        .map_err(|e| AiroiError::Argon2(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| AiroiError::Argon2(e.to_string()))?;
    Ok(key)
}

pub fn save_keypair_to_encrypted_file(kp: &KeyPair, passphrase: &str) -> Result<PathBuf> {
    let serialized = serialize_keypair(kp)?;

    let m = 1 << 15;
    let t = 3;
    let p = 1;

    let mut salt = [0u8; 16];
    OsRng.try_fill_bytes(&mut salt)?;
    let mut nonce = [0u8; 24];
    OsRng.try_fill_bytes(&mut nonce)?;

    let key = derive_key(passphrase, &salt, m, t, p)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| AiroiError::XChaCha20Poly1305(e.to_string()))?;
    let ct = cipher.encrypt(&nonce.into(), serialized.as_slice())
        .map_err(|e| AiroiError::XChaCha20Poly1305(e.to_string()))?;

    let mut key_mut = key;
    key_mut.zeroize();

    let enc = EncryptedKeystore {
        salt_b64: general_purpose::STANDARD.encode(&salt),
        nonce_b64: general_purpose::STANDARD.encode(&nonce),
        ct_b64: general_purpose::STANDARD.encode(&ct),
        argon_m: m,
        argon_t: t,
        argon_p: p,
    };

    let path = keystore_path()?;
    std::fs::write(&path, serde_json::to_string(&enc)?)?;
    Ok(path)
}

pub fn load_keypair_from_encrypted_file(passphrase: &str) -> Result<KeyPair> {
    let path = keystore_path()?;
    let s = std::fs::read_to_string(&path)?;
    let enc: EncryptedKeystore = serde_json::from_str(&s)?;
    let salt = general_purpose::STANDARD.decode(&enc.salt_b64)?;
    let nonce = general_purpose::STANDARD.decode(&enc.nonce_b64)?;
    let ct = general_purpose::STANDARD.decode(&enc.ct_b64)?;

    let key = derive_key(passphrase, &salt, enc.argon_m, enc.argon_t, enc.argon_p)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| AiroiError::XChaCha20Poly1305(e.to_string()))?;
    let plain_text = cipher.decrypt(nonce.as_slice().into(), ct.as_ref())
        .map_err(|e| AiroiError::XChaCha20Poly1305(e.to_string()))?;

    let mut key_mut = key;
    key_mut.zeroize();

    let kp: KeyPair = serde_json::from_slice(&plain_text)?;
    Ok(kp)
}
















