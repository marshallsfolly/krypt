//! The mailbox over HTTP: each request frame is one `POST /v1/frame`; the
//! response body is the response frame (204 when the mailbox had none).
//! The same API is served by the Cloudflare edge and the local dev mailbox.

use std::time::Duration;

use krypt_wire::frame::HEADER_SIZE;
use krypt_wire::limits::FRAME_BODY_MAX;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mailbox request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("mailbox answered with status {0}")]
    Status(u16),
    #[error("mailbox response exceeds the frame limit")]
    TooLarge,
    #[error("tls: {0}")]
    Tls(String),
}

#[derive(Clone, Debug)]
pub struct HttpMailbox {
    client: reqwest::Client,
    endpoint: String,
    base: String,
}

impl HttpMailbox {
    /// `base` is the mailbox's root URL, e.g. `https://api.krypt.chat`.
    pub fn new(base: &str) -> Result<HttpMailbox, Error> {
        crate::install_crypto_provider();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .pool_idle_timeout(Duration::from_secs(60))
            .build()?;
        Ok(HttpMailbox {
            client,
            endpoint: format!("{}/v1/frame", base.trim_end_matches('/')),
            base: base.trim_end_matches('/').to_owned(),
        })
    }

    fn part_url(&self, route: &[u8; 16], file: &[u8; 16], part: u32) -> String {
        let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
        format!("{}/v1/file/{}/{}/{part}", self.base, hex(route), hex(file))
    }

    /// Stores one sealed file part with its proof (`krypt-auth`); returns
    /// the HTTP status: 201 stored, 200 already stored, 409 stale proof.
    pub async fn put_part(
        &self,
        route: &[u8; 16],
        file: &[u8; 16],
        part: u32,
        auth: &str,
        body: Vec<u8>,
    ) -> Result<u16, Error> {
        let response = self
            .client
            .put(self.part_url(route, file, part))
            .header("content-type", "application/octet-stream")
            .header("krypt-auth", auth)
            .timeout(Duration::from_secs(120))
            .body(body)
            .send()
            .await?;
        Ok(response.status().as_u16())
    }

    /// Fetches one sealed file part, refusing more than `max` bytes; `None`
    /// if it is not (or no longer) stored.
    pub async fn get_part(
        &self,
        route: &[u8; 16],
        file: &[u8; 16],
        part: u32,
        max: usize,
    ) -> Result<Option<Vec<u8>>, Error> {
        let response = self
            .client
            .get(self.part_url(route, file, part))
            .timeout(Duration::from_secs(120))
            .send()
            .await?;
        match response.status().as_u16() {
            200 => {
                let body = response.bytes().await?;
                if body.len() > max {
                    return Err(Error::TooLarge);
                }
                Ok(Some(body.to_vec()))
            }
            404 => Ok(None),
            status => Err(Error::Status(status)),
        }
    }

    /// Sends one request frame and returns the response frame, if any.
    pub async fn request(&self, frame: Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
        let response = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/octet-stream")
            .body(frame)
            .send()
            .await?;
        match response.status().as_u16() {
            200 => {
                let body = response.bytes().await?;
                if body.len() > HEADER_SIZE + FRAME_BODY_MAX as usize {
                    return Err(Error::TooLarge);
                }
                Ok(Some(body.to_vec()))
            }
            204 => Ok(None),
            status => Err(Error::Status(status)),
        }
    }
}
