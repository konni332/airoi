mod keyring;
mod encrypted_file;

use crate::keys::KeyPair;
use zeroize::Zeroize;
use crate::error::Result;
use crate::storage::keyring::{load_keypair_from_keyring, save_keypair_to_keyring};

pub struct LocalKeyFile {
    pub private_key: String,
    pub public_key: String,
    pub created_at: String,
}

pub fn serialize_keypair(kp: &KeyPair) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(kp)?;
    Ok(bytes)
}

pub fn zeroize_keypair_inplace(kp: &mut KeyPair) {
    kp.private_key.x25519_key.0.zeroize();
    kp.private_key.x25519_key.1.zeroize();

    kp.private_key.ed25519_key.0.zeroize();
    kp.private_key.ed25519_key.1.zeroize();
}

pub fn store_keypair(kp: &KeyPair) -> Result<()> {
    save_keypair_to_keyring("airoi", "default", kp)?;
    Ok(())
}

pub fn fetch_local_keypair() -> Result<KeyPair> {
    load_keypair_from_keyring("airoi", "default")
}
