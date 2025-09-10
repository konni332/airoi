use thiserror::Error;

#[derive(Error, Debug)]
pub enum AiroiError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("OS Error: {0}")]
    Os(#[from] rand::rand_core::OsError),
    
    #[error("Serde Error: {0}")]
    Serde(#[from] serde_json::Error),
    
    #[error("Base58 Decode-Error: {0}")]
    Base58(#[from] bs58::decode::Error),
    
    #[error("Base58 Encode-Error: {0}")]
    Base58Encode(#[from] bs58::encode::Error),
    
    #[error("Snow Error: {0}")]
    Snow(#[from] snow::Error),
    
    #[error("Remote Static-Error: {0}")]
    RemoteStatic(String),
    
    #[error("Unknown Sender: {0}")]
    UnknownSender(String),
    
    #[error("Sender not trusted: {0}")]
    SenderNotTrusted(String),

    #[error("Keyring Error: {0}")]
    Keyring(#[from] keyring::Error),

    #[error("Base64 Decode Error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("Argon2 Error: {0}")]
    Argon2(String),

    #[error("XChaCha20Poly1305 Error: {0}")]
    XChaCha20Poly1305(String),
}

pub type Result<T> = std::result::Result<T, AiroiError>;