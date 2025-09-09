use std::fs;
use std::path::PathBuf;
use std::ptr::hash;
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::{TryRngCore};
use sha2::{Digest, Sha512};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use crate::keys::{Key, KeyPair};
use crate::error::Result;
use crate::util::get_airoi_dir;

pub fn generate_key_pair() -> Result<KeyPair> {
    let mut seed = [0u8; 32];
    OsRng.try_fill_bytes(&mut seed)?;

    let ed_sk = SigningKey::from_bytes(&seed);
    let ed_vk: VerifyingKey = ed_sk.verifying_key();

    let x_sk = ed25519_to_x25519(&ed_sk.to_bytes());
    let x_pk = x25519(x_sk, X25519_BASEPOINT_BYTES);

    let private_key = Key::new(ed_sk.to_bytes().to_vec(), x_sk.to_vec());
    let public_key = Key::new(ed_vk.to_bytes().to_vec(), x_pk.to_vec());

    Ok(KeyPair {
        private_key,
        public_key,
        created_at: Utc::now().to_rfc3339(),
    })
}

pub fn ed25519_to_x25519(ed_bytes: &[u8]) -> [u8; 32] {
    let hash = Sha512::digest(&ed_bytes);
    let mut x_sk = [0u8; 32];
    x_sk.copy_from_slice(&hash[0..32]);

    x_sk[0] &= 248;
    x_sk[31] &= 127;
    x_sk[31] |= 64;
    x_sk
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

pub fn fetch_local_key_pair() -> Result<KeyPair> {
    let mut path = get_airoi_dir();
    path.push("keys.json");
    let key_pair = serde_json::from_str::<KeyPair>(&fs::read_to_string(&path)?)?;
    Ok(key_pair)
}

pub fn get_fingerprint(key_bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(key_bytes);

    let finger_print = hasher.finalize();
    let fingerprint_bs58 = bs58::encode(finger_print).into_string();
    fingerprint_bs58
}

impl KeyPair {
    pub fn fingerprint_ed(&self) -> &str {
        self.public_key.fingerprint_ed()
    }
    pub fn fingerprint_x(&self) -> &str {
        self.public_key.fingerprint_x()
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