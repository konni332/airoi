use anyhow::bail;
use snow::params::NoiseParams;
use tokio::net::TcpListener;
use airoi_core::keys::contacts::{get_contacts, Contact};
use airoi_core::keys::key_gen::{generate_key_pair, fetch_local_key_pair, store_key_pair};
use airoi_core::message::receive::handle_connection;
use airoi_core::message::send::send;
use crate::cli::parser::{AiroiCommand, Cli};

pub const DEFAULT_ADDRESS: &str = "0.0.0.0:4444";

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
        }
        AiroiCommand::ListContacts => {
            list_contacts()?;
        }
        AiroiCommand::Receive { addr } => {
            let addr = match addr {
                Some(addr) => addr,
                None => DEFAULT_ADDRESS,
            };

            let key_pair = fetch_local_key_pair()?;
            let local_priv = key_pair.private_key().x25519_key_raw().to_vec();


            let contacts = get_contacts()?;
            let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse()?;


            let listener = TcpListener::bind(&addr).await?;
            println!("aioroi receiver listening on {}", addr);

            loop {
                let (mut socket, peer_addr) = listener.accept().await?;
                println!("New connection from {}", peer_addr);

                let contacts = contacts.clone();
                let local_priv = local_priv.clone();
                let params = params.clone();

                tokio::spawn(async move {
                    let builder = snow::Builder::new(params);
                    let builder = match builder.local_private_key(&local_priv) {
                        Ok(builder) => builder,
                        Err(e) => {
                            eprintln!("error setting local private key: {:?}", e);
                            return;
                        }
                    };

                    if let Err(e) = handle_connection(builder, &mut socket, &contacts).await {
                        eprintln!("connection error from {}: {:?}", peer_addr, e);
                    }
                });
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
    let local_keys = fetch_local_key_pair()?;
    println!("Local ed fp: {}", local_keys.fingerprint_ed());
    println!("Local ed k: {}", local_keys.public_key().ed25519_key());
    println!("Local x fp: {}", local_keys.fingerprint_x());
    println!("Local x k: {}", local_keys.public_key().x25519_key());
    let contacts = get_contacts()?;
    println!("Contacts:");
    if contacts.is_empty() {
        return Ok(println!("    No contacts found"));
    }
    for contact in contacts {
        println!("    {}:", contact.name);
        println!("        ed fp: {}", contact.fingerprint_ed());
        println!("        ed k: {}", contact.public_key().ed25519_key());
        println!("        x fp: {}", contact.fingerprint_x());
        println!("        x k: {}", contact.public_key().x25519_key());
    }
    Ok(())
}