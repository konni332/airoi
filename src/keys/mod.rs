use serde::{Deserialize, Serialize};
use crate::keys::key_gen::get_fingerprint;

pub mod key_gen;
pub mod contacts;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyPair {
    pub(crate) private_key: Key,
    pub(crate) public_key: Key,
    pub(crate) created_at: String,
}

impl KeyPair {
    pub fn private_key(&self) -> &Key {
        &self.private_key
    }
    pub fn public_key(&self) -> &Key {
        &self.public_key
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Key {
    pub(crate) x25519_key: (Vec<u8>, String),
    pub(crate) ed25519_key: (Vec<u8>, String),
    pub(crate) fingerprint_ed: String,
    pub(crate) fingerprint_x: String,
}

impl Key {
    pub fn new(raw_ed25519_key: Vec<u8>, raw_x25519_key: Vec<u8>) -> Key {
        let fingerprint_ed = get_fingerprint(&raw_ed25519_key);

        let ed25519_str = bs58::encode(&raw_ed25519_key).into_string();
        let ed25519_key = (raw_ed25519_key, ed25519_str);

        let fingerprint_x = get_fingerprint(&raw_x25519_key);

        let x25519_str = bs58::encode(&raw_x25519_key).into_string();
        let x25519_key = (raw_x25519_key, x25519_str);

        Key {
            ed25519_key,
            x25519_key,
            fingerprint_ed,
            fingerprint_x,
        }
    }
    pub fn ed25519_key(&self) -> &str {
        &self.ed25519_key.1
    }
    pub fn ed25519_key_raw(&self) -> &[u8] {
        &self.ed25519_key.0
    }
    pub fn x25519_key(&self) -> &str {
        &self.x25519_key.1
    }
    pub fn x25519_key_raw(&self) -> &[u8] {
        &self.x25519_key.0
    }
    pub fn fingerprint_ed(&self) -> &str {
        &self.fingerprint_ed
    }
    pub fn fingerprint_x(&self) -> &str {
        &self.fingerprint_x
    }
}