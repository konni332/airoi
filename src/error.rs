use thiserror::Error;

#[derive(Error, Debug)]
pub enum AiroiError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("OS Error: {0}")]
    Os(#[from] rand::rand_core::OsError),
    
    #[error("Serde Error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, AiroiError>;