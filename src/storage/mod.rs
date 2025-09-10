mod keyring;
mod encrypted_file;

use crate::keys::KeyPair;
use zeroize::Zeroize;
use crate::error::Result;
use crate::storage::encrypted_file::get_passphrase;
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
    if save_keypair_to_keyring("airoi", "default", kp).is_ok() {
        println!("Keypair stored in OS specific vault");
        return Ok(());
    }
    println!("OS Keyring not available. Storing keypair in encrypted file");
    let pass = rpassword::prompt_password("Choose a passphrase: ")?;
    let path = encrypted_file::save_keypair_to_encrypted_file(kp, &pass)?;
    println!("Keypair stored in encrypted file: {}", path.display());
    Ok(())
}

pub fn fetch_local_keypair() -> Result<KeyPair> {
    match load_keypair_from_keyring("airoi", "default") {
        Ok(kp) => Ok(kp),
        Err(_) => {
            let pass = get_passphrase();
            let kp = encrypted_file::load_keypair_from_encrypted_file(&pass)?;
            Ok(kp)
        }
    }
}
