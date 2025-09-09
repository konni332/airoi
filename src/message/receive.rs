use chrono::Utc;
use inquire::{Confirm, Text};
use sha2::{Digest, Sha256};
use snow::params::NoiseParams;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use crate::error::{Result, AiroiError};
use crate::keys::contacts::{get_contacts, store_contacts, Contact};
use crate::message::{read_frame, write_frame, Message};
use crate::storage::fetch_local_keypair;

pub async fn handle_connection(
    builder: snow::Builder<'_>,
    socket: &mut tokio::net::TcpStream,
    contacts: &[Contact],
    tx: mpsc::Sender<Message>,
) -> Result<()> {
    let mut noise = builder.build_responder()?;
    
    // ==================== Handshake ====================
    
    // Handshake msg 1: read from initiator
    let msg1 = read_frame(socket).await?;
    let mut buf = vec![0u8; 1024];
    let _payload1 = noise.read_message(&msg1, &mut buf)?;
    // ignore for now!
    
    // Handshake msg 2: respond
    let mut out_buf = vec![0u8; 1024];
    let len2 = noise.write_message(&[], &mut out_buf)?;
    write_frame(socket, &out_buf[..len2]).await?;
    
    // Handshake msg 3: read the final initiator message
    let msg3 = read_frame(socket).await?;
    let _payload3 = noise.read_message(&msg3, &mut buf)?;
    
    // ==================== Handshake Done ====================

    let mut matched_contact: Option<Contact> = None;
    let remote_static_opt = noise.get_remote_static();
    if let Some(remote_static) = remote_static_opt {
        let mut hasher = Sha256::new();
        hasher.update(remote_static);
        let fingerprint = hasher.finalize();
        let fingerprint_bs58 = bs58::encode(fingerprint).into_string();
        println!("Handshake complete; remote static key fingerprint (sha256 base58): {}", fingerprint_bs58);

        for contact in contacts {
            if contact.fingerprint_x() == fingerprint_bs58 {
                    matched_contact = Some(contact.clone());
                break; 
            }
        }
        match matched_contact {
            None => {
                let peer_addr = socket.peer_addr()?.to_string();
                let new_contact = match tofu(remote_static.to_vec(), &peer_addr) {
                    Ok(new_contact) => new_contact,
                    Err(AiroiError::SenderNotTrusted(_)) => {
                        eprintln!("Closing connection. Sender not trusted.");
                        return Ok(())
                    }
                    Err(e) => {
                        return Err(e);
                    }
                };
                matched_contact = Some(new_contact);
            }
            _ => {}
        }
    }
    else {
        return Err(AiroiError::RemoteStatic("handshake did not reveal remote static key".to_string()));
    }
    
    // Convert handshake state into transport mode (symmetric encryption)
    let mut transport = noise.into_transport_mode()?;

    loop {
        let frame = match read_frame(socket).await {
            Ok(frame) => frame,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
                eprintln!("error reading frame: {:?}", e);
                break;
            }
        };
        
        let mut plaintext = vec![0u8; 65535]; // big enough buffer
        match transport.read_message(&frame, &mut plaintext) { 
            Ok(sz) => {
                plaintext.truncate(sz);
                let s = String::from_utf8_lossy(&plaintext).to_string();
                let message = Message {
                    sender: matched_contact.clone().unwrap(), // safe, we would have returned an error if this was None
                    message: s,
                    received: Utc::now().to_rfc3339(),
                };

                if tx.send(message).await.is_err() {
                    eprintln!("receiver dropped, stopping connection");
                    break;
                }
            }
            Err(e) => {
                eprintln!("error reading message: {:?}", e);
                break;
            }
        }
    }
    
    Ok(())
}


pub const DEFAULT_ADDRESS: &str = "0.0.0.0:4444";

pub async fn receive(addr: Option<String>, tx: mpsc::Sender<Message>) -> Result<()> {
    let addr = addr.unwrap_or(DEFAULT_ADDRESS.to_string());

    let key_pair = fetch_local_keypair()?;
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
        let tx_clone = tx.clone();

        tokio::spawn(async move {
            let builder = snow::Builder::new(params);
            let builder = match builder.local_private_key(&local_priv) {
                Ok(builder) => builder,
                Err(e) => {
                    eprintln!("error setting local private key: {:?}", e);
                    return;
                }
            };

            if let Err(e) = handle_connection(builder, &mut socket, &contacts, tx_clone).await {
                eprintln!("connection error from {}: {:?}", peer_addr, e);
            }
        });
    }
}

pub fn tofu(raw_remote_static: Vec<u8>, peer_addr: &str) -> Result<Contact> {
    let mut contacts = get_contacts()?;
    let name = prompt_tofu()?;

    let new_contact = Contact::new_tofu(name.to_string(), raw_remote_static, peer_addr);
    contacts.push(new_contact.clone());
    store_contacts(contacts)?;
    println!("Contact '{}' added", name);
    Ok(new_contact)
}

pub fn prompt_tofu() -> Result<String> {
    println!("No contact found with this public key. Do you want to add a new contact?");
    let save = Confirm::new("Do you want to save this contact?")
        .prompt()
        .unwrap_or(false);

    if !save {
        return Err(AiroiError::SenderNotTrusted("User denied TOFU".to_string()));
    }
    let name = Text::new("Name:")
        .prompt()
        .unwrap_or_else(|_| "Unknown".to_string());
    Ok(name)
}


