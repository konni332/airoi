use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::keys::contacts::Contact;

pub mod receive;
pub mod send;

pub struct Message {
    pub sender: Contact,
    pub message: String,
    pub received: String,
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:  {}: {}", self.received, self.sender.name, self.message)
    }
}

async fn read_frame(stream: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame(stream: &mut tokio::net::TcpStream, data: &[u8]) -> std::io::Result<()> {
    let len = data.len();
    if len > u16::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "data too long to send over tcp")
        );
    }
    let len_buf = (len as u16).to_be_bytes();
    stream.write_all(&len_buf).await?;
    stream.write_all(data).await?;
    Ok(())
}
