#[cfg(test)]
mod integration {
    use std::sync::Arc;
    use snow::Builder;
    use snow::params::NoiseParams;
    use tokio::net::TcpListener;
    use airoi_core::keys::contacts::Contact;
    use airoi_core::keys::key_gen::generate_key_pair;
    use airoi_core::message::receive::handle_connection;
    use airoi_core::message::send::send;

    #[tokio::test]
    async fn test_send_and_receive() {
        let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap();

        let keypair = generate_key_pair().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let contacts = Arc::new(vec![Contact::new(
            "test-self".to_string(),
            keypair.public_key().ed25519_key_raw().to_vec(),
            &addr.to_string()
        )]);

        let (tx, mut rx) = tokio::sync::mpsc::channel(1);

        {
            let contacts = contacts.clone();
            let params = params.clone();
            let keypair = keypair.clone();
            let tx = tx.clone();

            tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut builder = Builder::new(params.clone());
                builder = builder.local_private_key(keypair.private_key().x25519_key_raw()).unwrap();
                let _ = handle_connection(builder, &mut socket, &contacts, tx).await;
            });
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let contact = contacts[0].clone();
        send(contact, "test message").await.unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.message, "test message");
    }
}