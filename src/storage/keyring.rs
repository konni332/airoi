use base64::Engine;
use base64::engine::general_purpose;
use crate::keys::KeyPair;

use crate::error::Result;
use crate::storage::serialize_keypair;
use keyring::{Entry};

pub fn save_keypair_to_keyring(service: &str, account: &str, kp: &KeyPair) -> Result<()> {
    let serialized = serialize_keypair(&kp)?;
    let encoded = general_purpose::STANDARD.encode(&serialized);

    let kr = Entry::new(service, account)?;
    kr.set_password(&encoded)?;
    Ok(())
}

pub fn load_keypair_from_keyring(service: &str, account: &str) -> Result<KeyPair> {
    let kr = Entry::new(service, account)?;
    let encoded = kr.get_password()?;
    
    let bytes = general_purpose::STANDARD.decode(&encoded)?;
    let kp: KeyPair = serde_json::from_slice(&bytes)?;
    Ok(kp)
}