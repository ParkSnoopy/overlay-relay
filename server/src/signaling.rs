//! Bounded direct-link signaling, never an unrestricted payload byte stream.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    select,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::{
    error::{Error, Result},
    frame::{read_frame, send_frame},
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Message {
    t: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    m: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    s: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    d: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    e: String,
}

fn method(name: &str) -> bool {
    matches!(name, "webrtc" | "ice")
}

impl Message {
    fn valid_data(&self) -> bool {
        let Some(data) = self.d.as_ref().and_then(serde_json::Value::as_object) else {
            return false;
        };
        let text = |key: &str, limit: usize| {
            data.get(key)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|text| !text.is_empty() && text.len() <= limit && !text.contains('\0'))
        };
        let list = |key: &str| {
            data.get(key)
                .and_then(serde_json::Value::as_array)
                .is_some_and(|items| {
                    !items.is_empty()
                        && items.len() <= 32
                        && items.iter().all(|item| {
                            item.as_str().is_some_and(|text| {
                                !text.is_empty()
                                    && text.len() <= 1024
                                    && !text.chars().any(char::is_control)
                            })
                        })
                })
        };
        match self.s.as_str() {
            "webrtc" => {
                data.len() == 2
                    && data.get("type").and_then(serde_json::Value::as_str) == Some(self.t.as_str())
                    && text("sdp", 12 * 1024)
                    && data["sdp"].as_str().is_some_and(|sdp| {
                        sdp.starts_with("v=0\r\n") && sdp.contains("m=application ")
                    })
            }
            "ice" => data.len() == 3 && text("u", 256) && text("p", 256) && list("c"),

            _ => false,
        }
    }

    fn valid(&self) -> bool {
        match self.t.as_str() {
            "hello" => {
                !self.m.is_empty()
                    && self.m.len() <= 2
                    && self.m.iter().all(|name| method(name))
                    && self.s.is_empty()
                    && self.d.is_none()
                    && self.e.is_empty()
            }
            "offer" | "answer" => self.valid_data() && self.m.is_empty() && self.e.is_empty(),
            "done" => method(&self.s) && self.d.is_none() && self.m.is_empty() && self.e.is_empty(),
            "fail" => {
                matches!(
                    self.e.as_str(),
                    "busy" | "unsupported method" | "method failed"
                ) && self.s.is_empty()
                    && self.d.is_none()
                    && self.m.is_empty()
            }
            "sync" | "next" | "end" => {
                self.s.is_empty() && self.d.is_none() && self.m.is_empty() && self.e.is_empty()
            }
            _ => false,
        }
    }
}

async fn forward(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
) -> Result<()> {
    let mut bytes = 0;
    let mut offered = Vec::new();
    for index in 0..32 {
        let message: Message = read_frame(reader).await?;
        if !message.valid()
            || (index == 0 && !matches!(message.t.as_str(), "hello" | "fail"))
            || (index == 0 && message.e == "method failed")
            || (index > 0 && message.t == "hello")
        {
            return Err(Error::Config("invalid direct signaling"));
        }
        if matches!(message.t.as_str(), "offer" | "answer") {
            if offered.contains(&message.s) {
                return Err(Error::Config("repeated direct method"));
            }
            offered.push(message.s.clone());
        }
        bytes += serde_json::to_vec(&message)?.len();
        if bytes > 64 * 1024 {
            return Err(Error::Config("direct signaling budget exceeded"));
        }
        send_frame(writer, &message).await?;
        if matches!(message.t.as_str(), "done" | "end")
            || (message.t == "fail" && message.e != "method failed")
        {
            return Ok(());
        }
    }
    Err(Error::Config("too many direct signaling messages"))
}

/// Exchanges only validated JSON messages, for at most 90 seconds and 64 `KiB`
/// per direction. Flow/account limits are enforced by the ordinary open path.
pub async fn exchange(mut left: TcpStream, mut right: TcpStream, cancel: CancellationToken) {
    let (mut lr, mut lw) = left.split();
    let (mut rr, mut rw) = right.split();
    select! {
        () = cancel.cancelled() => {},
        _ = timeout(Duration::from_secs(90), async {
            select! {
                result = forward(&mut lr, &mut rw) => result,
                result = forward(&mut rr, &mut lw) => result,
            }
        }) => {},
    }
}
