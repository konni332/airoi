use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::error::AiroiError;

pub mod receive;
pub mod send;


async fn read_frame(stream: &mut tokio::net::TcpStream) -> crate::error::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame(stream: &mut tokio::net::TcpStream, data: &[u8]) -> crate::error::Result<()> {
    let len = data.len();
    if len > u16::MAX as usize {
        return Err(AiroiError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large"
        )));
    }
    let len_buf = (len as u16).to_be_bytes();
    stream.write_all(&len_buf).await?;
    stream.write_all(data).await?;
    Ok(())
}
