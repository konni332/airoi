use clap::{Parser, Subcommand};

#[derive(Parser, Debug, Clone)]
#[clap(
    version = "0.1.0",
    author = "konni332",
    about = "EEENCRYYYPTIOOOON",
)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: AiroiCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum AiroiCommand {
    /// Generate a new key pair and store it in the default location (depends on OS)
    KeyGen,
    /// Get the fingerprint of the current key pair in the default location (depends on OS)
    Fingerprint,
    /// Add someone to your contacts
    AddContact {
        /// Name of the contact
        name: String,
        /// Public key of the contact
        public_key: String,
        /// Address of the contact
        address: String,
    },
    /// Remove someone from your contacts
    RemoveContact {
        /// Name of the contact
        name: String,
    },
    /// List all contacts
    ListContacts,
    
    Receive { addr: Option<String> },
    
    Send { name: String, message: String },
}
