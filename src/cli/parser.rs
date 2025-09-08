use clap::Parser;

#[derive(Parser)]
#[clap(
    version = "0.1.0",
    author = "konni332",
    about = "EEENCRYYYPTIOOOON",
)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: AiroiCommand,
}

#[derive(Parser)]
pub enum AiroiCommand {
    /// Generate a new key pair and store it in the default location (depends on OS)
    KeyGen,
    /// Get the fingerprint of the current key pair in the default location (depends on OS)
    Fingerprint,
}
