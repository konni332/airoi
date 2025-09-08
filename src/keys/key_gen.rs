use std::fs;
use std::path::PathBuf;
use std::ptr::hash;
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::{TryRngCore};
use sha2::Digest;
use crate::keys::KeyPair;
use crate::error::Result;
use crate::util::get_airoi_dir;

pub fn generate_key_pair() -> Result<KeyPair> {
    let mut seed = [0u8; 32];
    OsRng.try_fill_bytes(&mut seed)?;

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key: VerifyingKey = signing_key.verifying_key();


    Ok(KeyPair {
        private_key: signing_key.to_bytes().to_vec(),
        public_key: verifying_key.to_bytes().to_vec(),
        created_at: Utc::now().to_rfc3339(),
    })

}

pub fn store_key_pair(key_pair: KeyPair) -> Result<PathBuf> {
    let mut path = dirs::config_dir().unwrap_or_else(|| {PathBuf::from(".")});
    path.push("airoi");
    fs::create_dir_all(&path)?;
    path.push("keys.json");

    let json = serde_json::to_string_pretty(&key_pair)?;
    fs::write(&path, json)?;
    Ok(path)
}

pub fn get_key_pair() -> Result<KeyPair> {
    let mut path = get_airoi_dir();
    path.push("keys.json");
    let key_pair = serde_json::from_str::<KeyPair>(&std::fs::read_to_string(&path)?)?;
    Ok(key_pair)
}

pub fn get_fingerprint(public_key: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(public_key);

    let finger_print = hasher.finalize();
    let fingerprint_bs58 = bs58::encode(finger_print).into_string();
    fingerprint_bs58
}

impl KeyPair {
    pub fn finger_print(&self) -> String {
        get_fingerprint(&self.public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_pair() {
        let keys = generate_key_pair().unwrap();
        println!("{:#?}", keys);
    }
}