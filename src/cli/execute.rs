use anyhow::bail;
use airoi_core::keys::key_gen::{generate_key_pair, get_key_pair, store_key_pair};
use crate::cli::parser::{AiroiCommand, Cli};

pub fn execute_cli_command(cli: &Cli) -> anyhow::Result<()> {
    match &cli.command { 
        AiroiCommand::KeyGen => {
            let key_pair = generate_key_pair()?;
            let stored_at = store_key_pair(key_pair)?;
            println!("New key pair stored at: {}", stored_at.to_string_lossy());
            output_fingerprint()?;
        }
        AiroiCommand::Fingerprint => {
            output_fingerprint()?;
        }
        _ => {
            bail!("Command not implemented")
        }
    }
    Ok(())
}

fn output_fingerprint() -> anyhow::Result<()> {
    let current = get_key_pair()?;
    let fingerprint = airoi_core::keys::key_gen::get_fingerprint(&current);
    println!("Fingerprint: {}", fingerprint);
    Ok(())
}