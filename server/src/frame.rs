//! Length-prefixed JSON frames and 16-bit length-prefixed datagram records.

use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::error::{Error, Result};
use crate::protocol::{MAX_DATAGRAM, MAX_FRAME};

/// Deadline for one outbound frame, so a stalled peer cannot pin a task.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Reads one length-prefixed JSON frame.
///
/// # Errors
/// Returns `Error::Protocol` for a zero or oversized length, `Error::Io` when
/// the stream ends early, and `Error::Json` when the payload does not decode.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header).await?;
    let size = usize::from(u16::from_be_bytes(header));
    if size == 0 || size > MAX_FRAME {
        return Err(Error::Protocol("overlay frame size is out of bounds"));
    }
    let mut payload = vec![0_u8; size];
    reader.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}

/// Writes one length-prefixed JSON frame.
///
/// # Errors
/// Returns `Error::Protocol` when the encoded payload is empty or exceeds the
/// frame bound, and `Error::Io` when the write fails.
pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let payload = serde_json::to_vec(value)?;
    if payload.is_empty() || payload.len() > MAX_FRAME {
        return Err(Error::Protocol("overlay frame size is out of bounds"));
    }
    let header = u16::try_from(payload.len())
        .map_err(|_| Error::Protocol("overlay frame size is out of bounds"))?
        .to_be_bytes();
    let mut frame = Vec::with_capacity(payload.len() + header.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&payload);
    writer.write_all(&frame).await?;
    Ok(())
}

/// Writes one frame under the hub's write deadline.
///
/// # Errors
/// Returns `Error::Timeout` when the write does not finish in time, otherwise
/// the errors of [`write_frame`].
pub async fn send_frame<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    match timeout(WRITE_TIMEOUT, write_frame(writer, value)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(Error::Timeout),
    }
}

/// Writes one UDP payload as a 16-bit length-prefixed record.
///
/// # Errors
/// Returns `Error::Protocol` when the payload exceeds [`MAX_DATAGRAM`] bytes,
/// and `Error::Io` when the write fails.
pub async fn write_datagram<W>(writer: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > MAX_DATAGRAM {
        return Err(Error::Protocol("overlay datagram is too large"));
    }
    let size = u16::try_from(payload.len())
        .map_err(|_| Error::Protocol("overlay datagram is too large"))?;
    let mut record = Vec::with_capacity(payload.len() + 2);
    record.extend_from_slice(&size.to_be_bytes());
    record.extend_from_slice(payload);
    writer.write_all(&record).await?;
    Ok(())
}

/// Reads one datagram record into `buffer` and returns its payload length.
///
/// # Errors
/// Returns `Error::Protocol` when the record does not fit in `buffer`, and
/// `Error::Io` when the stream ends early.
pub async fn read_datagram<R>(reader: &mut R, buffer: &mut [u8]) -> Result<usize>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header).await?;
    let size = usize::from(u16::from_be_bytes(header));
    if size > buffer.len() {
        return Err(Error::Protocol("overlay datagram exceeds buffer"));
    }
    reader.read_exact(&mut buffer[..size]).await?;
    Ok(size)
}
