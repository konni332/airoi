use serde::{Deserialize, Serialize};

pub mod key_gen;
pub mod contacts;

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyPair {
    pub(crate) public_key: Vec<u8>,
    pub(crate) private_key: Vec<u8>,
    pub(crate) created_at: String,
}