use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::{TryRngCore};
use sha2::{Digest, Sha512};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use crate::keys::{Key, KeyPair};
use crate::error::Result;

pub fn generate_key_pair() -> Result<KeyPair> {
    let mut seed = [0u8; 32];
    OsRng.try_fill_bytes(&mut seed)?;

    let ed_sk = SigningKey::from_bytes(&seed);
    let ed_vk: VerifyingKey = ed_sk.verifying_key();

    let x_sk = ed25519_sk_to_x25519(&ed_sk.to_bytes());
    let x_pk = x25519(x_sk, X25519_BASEPOINT_BYTES);

    let private_key = Key::new(ed_sk.to_bytes().to_vec(), x_sk.to_vec());
    let public_key = Key::new(ed_vk.to_bytes().to_vec(), x_pk.to_vec());

    Ok(KeyPair {
        private_key,
        public_key,
        created_at: Utc::now().to_rfc3339(),
    })
}

/// Ed25519 Secret -> X25519 Secret
pub fn ed25519_sk_to_x25519(ed_bytes: &[u8]) -> [u8; 32] {
    let hash = Sha512::digest(&ed_bytes);
    let mut x_sk = [0u8; 32];
    x_sk.copy_from_slice(&hash[0..32]);

    x_sk[0] &= 248;
    x_sk[31] &= 127;
    x_sk[31] |= 64;
    x_sk
}

/// Ed25519 Public -> X25519 Public
pub fn ed25519_pk_to_x25519(ed_pk: &[u8]) -> [u8; 32] {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::montgomery::MontgomeryPoint;

    let ed_pk: [u8; 32] = ed_pk.try_into().expect("invalid ed pk");
    let compressed = CompressedEdwardsY(ed_pk);
    let ed_point = compressed.decompress().expect("invalid ed point");
    let mont_point: MontgomeryPoint = ed_point.to_montgomery();
    mont_point.to_bytes()
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
    fn test_ed2519_sk_to_x25519_deterministic() {
        let ed_sk = [1u8; 32];
        let x_sk1 = ed25519_sk_to_x25519(&ed_sk);
        let x_sk2 = ed25519_sk_to_x25519(&ed_sk);
        assert_eq!(x_sk1, x_sk2);
    }

    #[test]
    fn test_ed2519_pk_matches_sk_conversion() {
        let seed = [42u8; 32];
        let ed_sk = SigningKey::from_bytes(&seed);
        let ed_pl = ed_sk.verifying_key();

        let x_sk = ed25519_sk_to_x25519(&ed_sk.to_bytes());
        let x_pk_from_sk = x25519(x_sk, X25519_BASEPOINT_BYTES);

        let x_pk_from_pk = ed25519_pk_to_x25519(&ed_pl.to_bytes());

        assert_eq!(x_pk_from_sk, x_pk_from_pk);
    }

    #[test]
    fn test_generate_key_pair_valid() {
        let kp = generate_key_pair().expect("key pair generation failed");

        assert_eq!(kp.private_key().ed25519_key_raw().len(), 32);
        assert_eq!(kp.private_key().x25519_key_raw().len(), 32);
        assert_eq!(kp.public_key().ed25519_key_raw().len(), 32);
        assert_eq!(kp.public_key().x25519_key_raw().len(), 32);

        let derived_x_pub = ed25519_pk_to_x25519(kp.public_key().ed25519_key_raw());
        assert_eq!(derived_x_pub, kp.public_key().x25519_key_raw());
    }

    #[test]
    fn test_generate_key_pair_unique() {
        let kp1 = generate_key_pair().expect("key pair generation failed");
        let kp2 = generate_key_pair().expect("key pair generation failed");
        assert_ne!(kp1.public_key().ed25519_key_raw(), kp2.public_key().ed25519_key_raw());
        assert_ne!(kp1.public_key().x25519_key_raw(), kp2.public_key().x25519_key_raw());
    }
}