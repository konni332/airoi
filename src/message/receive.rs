use sha2::{Digest, Sha256};
use crate::error::{Result, AiroiError};
use crate::keys::contacts::Contact;
use crate::message::{read_frame, write_frame};

pub async fn handle_connection(
    builder: snow::Builder<'_>,
    socket: &mut tokio::net::TcpStream,
    contacts: &[Contact],
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
    
    let remote_static_opt = noise.get_remote_static();
    if let Some(remote_static) = remote_static_opt {
        let mut hasher = Sha256::new();
        hasher.update(remote_static);
        let fingerprint = hasher.finalize();
        let fingerprint_bs58 = bs58::encode(fingerprint).into_string();
        println!("Handshake complete; remote static key fingerprint (sha256 base58): {}", fingerprint_bs58);
        
        let mut matched_contact: Option<&Contact> = None;
        for contact in contacts {
            if contact.fingerprint_x() == fingerprint_bs58 {
                    matched_contact = Some(contact);
                break; 
            }
        }
        match matched_contact {
            None => {
                return Err(AiroiError::UnknownSender(fingerprint_bs58));
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
                let s = String::from_utf8_lossy(&plaintext);
                println!("received message: {}", s);
            }
            Err(e) => {
                eprintln!("error reading message: {:?}", e);
                break;
            }
        }
    }
    
    Ok(())
}











