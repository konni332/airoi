use std::path::PathBuf;
use argon2::{Argon2, Params};
use dirs::config_dir;
use rand::{RngCore, TryRngCore};
use rand::rngs::OsRng;
use crate::error::AiroiError;
use crate::error::Result;
use crate::keys::KeyPair;
use crate::storage::serialize_keypair;



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


















