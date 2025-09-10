use snow::Builder;
use snow::params::NoiseParams;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;
use crate::error::{AiroiError, Result};
use crate::keys::contacts::Contact;
use crate::keys::key_gen::{get_fingerprint};
use crate::message::{read_frame, write_frame};
use crate::storage::fetch_local_keypair;

pub async fn send(contact: Contact, msg: &str) -> Result<()> {
    let keys = fetch_local_keypair()?;

    let local_priv = keys.private_key().x25519_key_raw().to_vec();
    let _remote_pub = contact.public_key().x25519_key_raw().to_vec();

    let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse()?;
    let mut builder = Builder::new(params);
    builder = builder.local_private_key(&local_priv)?;

    let mut noise = builder.build_initiator()?;

    println!("Sending message to {}", contact.address());
    // ==== Tor Connection ====
    let torrc = crate::tor::config::setup_tor().await?;
    let hidden_service_dir = crate::tor::config::get_hidden_service_dir();
    let mut tor_child = crate::tor::config::start_tor_daemon(&torrc)?;
    let onion_addr = crate::tor::config::wait_for_onion(&hidden_service_dir).await?;
    println!("Your onion service address is: {}", onion_addr);

    let tor_stream =
        Socks5Stream::connect("127.0.0.1:9050", format!("{}:4444", contact.address())).await
            .map_err(|e| AiroiError::Onion(e.to_string()))?;
    let mut stream: TcpStream = tor_stream.into_inner();
    println!("connected to {}", contact.address());

    // Handshake
    let mut buf = vec![0u8; 1024];

    // msg1
    let mut msg1 = vec![0u8; 1024];
    let len1 = noise.write_message(&[], &mut msg1)?;
    write_frame(&mut stream, &msg1[..len1]).await?;

    // msg2
    let msg2 = read_frame(&mut stream).await?;
    noise.read_message(&msg2, &mut buf)?;

    // msg3
    let mut msg3 = vec![0u8; 1024];
    let len3 = noise.write_message(&[], &mut msg3)?;
    write_frame(&mut stream, &msg3[..len3]).await?;

    // handshake done
    let remote_static = noise.get_remote_static().unwrap();
    let fingerprint = get_fingerprint(&remote_static);
    println!("Handshake OK with remote, fingerprint: {}", fingerprint);

    let mut transport = noise.into_transport_mode()?;

    // send the actual message
    let mut cipher = vec![0u8; 65535]; // big enough buffer
    let len = transport.write_message(msg.as_bytes(), &mut cipher)?;
    write_frame(&mut stream, &cipher[..len]).await?;

    tor_child.kill()?;
    Ok(())
}