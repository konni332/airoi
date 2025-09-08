use serde::{Deserialize, Serialize};

pub mod key_gen;
pub mod contacts;

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyPair {
    pub(crate) public_key: String,
    pub(crate) finger_print: String,
    pub(crate) private_key: String,
    pub(crate) created_at: String,
}