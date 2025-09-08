use anyhow::bail;
use airoi_core::keys::contacts::Contact;
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

        // Contacts
        AiroiCommand::AddContact { name, finger_print } => {
            let new_contact = Contact {
                name: name.clone(),
                finger_pint: finger_print.clone(),
                added_at: chrono::Utc::now().to_rfc3339(),
            };
            airoi_core::keys::contacts::add_contact(new_contact)?;
        }
        AiroiCommand::RemoveContact { name } => {
            airoi_core::keys::contacts::remove_contact(name)?;
        }
        AiroiCommand::ListContacts => {
            list_contacts()?;
        }
        _ => {
            bail!("Command not implemented")
        }
    }
    Ok(())
}

fn output_fingerprint() -> anyhow::Result<()> {
    let current = get_key_pair()?;
    let fingerprint = current.finger_print();
    println!("Fingerprint: {}", fingerprint);
    Ok(())
}

fn list_contacts() -> anyhow::Result<()> {
    let contacts = airoi_core::keys::contacts::get_contacts()?;
    println!("Contacts:");
    if contacts.is_empty() {
        return Ok(println!("    No contacts found"));
    }
    for contact in contacts {
        println!("    {}: {}", contact.name, contact.finger_pint);
    }
    Ok(())
}