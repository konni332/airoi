use anyhow::bail;
use airoi_core::keys::contacts::{get_contacts, Contact};
use airoi_core::keys::key_gen::{generate_key_pair, fetch_local_key_pair, store_key_pair};
use airoi_core::message::receive::{receive};
use airoi_core::message::send::send;
use crate::cli::parser::{AiroiCommand, Cli};



pub async fn execute_cli_command(cli: &Cli) -> anyhow::Result<()> {
    match &cli.command {
        AiroiCommand::KeyGen => {
            let key_pair = generate_key_pair()?;
            let stored_at = store_key_pair(key_pair.clone())?;
            println!("New key pair stored at: {}", stored_at.to_string_lossy());
            println!("    Public key (ed25519): {}", key_pair.public_key().ed25519_key());
        }
        AiroiCommand::Fingerprint => {
            output_fingerprint()?;
        }

        // Contacts
        AiroiCommand::AddContact { name, public_key, address } => {
            let raw_ed_public_key = bs58::decode(public_key).into_vec()?;
            let new_contact = Contact::new(name.clone(), raw_ed_public_key, address);
            airoi_core::keys::contacts::add_contact(new_contact.clone())?;
            println!("Contact '{}' added. Public key (ed25519): {}", name, new_contact.public_key().ed25519_key());
        }
        AiroiCommand::RemoveContact { name } => {
            airoi_core::keys::contacts::remove_contact(name)?;
            println!("Contact '{}' removed", name);
        }
        AiroiCommand::ListContacts => {
            list_contacts()?;
        }
        AiroiCommand::Receive { addr } => {
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);

            let addr = addr.clone();
            tokio::spawn(async move {
                if let Err(e) = receive(addr, tx).await {
                    eprintln!("receive error: {}", e);
                }
            });

            while let Some(msg) = rx.recv().await {
                println!("{}", msg);
            }
        }
        AiroiCommand::Send { name, message } => {
            let contacts = get_contacts()?;
            for c in &contacts {
                if &c.name == name.as_str() {
                    send(c.clone(), message.as_str()).await?;
                    return Ok(());
                }
            }
            bail!("Contact not found")

        }
    }
    Ok(())
}

fn output_fingerprint() -> anyhow::Result<()> {
    let current = fetch_local_key_pair()?;
    let fingerprint = current.fingerprint_ed();
    println!("Fingerprint (ed25519): {}", fingerprint);
    Ok(())
}

fn list_contacts() -> anyhow::Result<()> {
    let contacts = get_contacts()?;
    println!("Contacts:");
    if contacts.is_empty() {
        return Ok(println!("    No contacts found"));
    }
    for contact in contacts {
        println!("    {}:", contact.name);
        println!("        fingerprint: {}", contact.fingerprint_ed());
    }
    Ok(())
}