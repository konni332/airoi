use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use crate::error::{AiroiError, Result};
use crate::util::get_airoi_dir;
use std::process::{Child, Command};

pub async fn setup_tor() -> Result<PathBuf>{
    let airoi_dir = get_airoi_dir();
    let torrc = airoi_dir.join("torrc");

    let tor_data = airoi_dir.join("tor_data");

    let hidden_service_dir = airoi_dir.join("tor_service");

    let mut f = tokio::fs::File::create(&torrc).await?;
    let content = format!(
        "DataDirectory {}\nHiddenServiceDir {}\nHiddenServicePort 4444 127.0.0.1:4444\nSocksPort auto\n",
        tor_data.display(),
        hidden_service_dir.display()
    );
    f.write_all(content.as_bytes()).await?;
    Ok(torrc)
}

pub fn start_tor_daemon(torrc: &PathBuf) -> Result<Child> {
    let child = Command::new("tor")
        .arg("-f")
        .arg(torrc)
        .spawn()?;
    Ok(child)
}

pub fn kill_tor_daemon(child: &mut Child) -> Result<()> {
    child.kill()?;
    Ok(())
}

pub async fn read_onion_addr(hidden_service_dir: &PathBuf) -> Result<String> {
    let hostname_path = hidden_service_dir.join("hostname");
    let addr = tokio::fs::read_to_string(hostname_path).await?;
    Ok(addr.trim().to_string())
}

pub fn get_hidden_service_dir() -> PathBuf {
    let airoi_dir = get_airoi_dir();
    let hidden_service_dir = airoi_dir.join("tor_service");
    hidden_service_dir
}

pub async fn wait_for_onion(hidden_service_dir: &PathBuf) -> Result<String> {
    println!("Waiting for .onion to be ready...");
    let hostname_path = hidden_service_dir.join("hostname");
    for _ in 0..20 {
        if let Ok(addr) = tokio::fs::read_to_string(&hostname_path).await {
            return Ok(addr.trim().to_string());
        }
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    }
    Err(AiroiError::Onion("Onion not ready".to_string()))
}

pub async fn wait_for_tor_ready() -> Result<()> {
    println!("Waiting for Tor to be ready...");
    for _ in 0..30 {
        if tokio::net::TcpStream::connect("127.0.0.1:9050").await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Err(AiroiError::Onion("Tor not ready in time".to_string()))
}














