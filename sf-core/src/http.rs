//! Shared async HTTP client with rate-limiting, default UA, and optional SOCKS5.

use crate::config::GlobalConfig;
use crate::error::{Error, Result};
use crate::ratelimit::RateLimiters;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

/// A thin wrapper over `reqwest::Client` that rate-limits per source.
#[derive(Clone)]
pub struct HttpClient {
    client: reqwest::Client,
    limiters: Arc<RateLimiters>,
    user_agent: String,
}

impl HttpClient {
    pub fn new(cfg: &GlobalConfig, limiters: Arc<RateLimiters>) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .user_agent(cfg._useragent.clone())
            .timeout(Duration::from_secs(cfg._fetchtimeout.max(1)))
            .gzip(true)
            .pool_max_idle_per_host(100);
        if let Some(proxy) = &cfg._socks_proxy {
            if !proxy.is_empty() {
                builder = builder.proxy(reqwest::Proxy::all(proxy)?);
            }
        }
        Ok(HttpClient {
            client: builder.build()?,
            limiters,
            user_agent: cfg._useragent.clone(),
        })
    }

    /// A client with library defaults (used for ad-hoc contexts / tests).
    pub fn default_client() -> Result<Self> {
        Self::new(&GlobalConfig::default(), Arc::new(RateLimiters::new()))
    }

    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    pub fn raw(&self) -> &reqwest::Client {
        &self.client
    }

    /// GET returning the body as text.
    pub async fn get_text(&self, source: &str, url: &str) -> Result<String> {
        self.limiters.until_ready(source).await;
        let resp = self.client.get(url).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if status.is_success() {
            Ok(text)
        } else {
            Err(Error::Http(format!("{url} -> HTTP {status}")))
        }
    }

    /// GET returning the (status code, body text) regardless of status.
    pub async fn get_status_text(&self, source: &str, url: &str) -> Result<(u16, String)> {
        self.limiters.until_ready(source).await;
        let resp = self.client.get(url).send().await?;
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        Ok((status, text))
    }

    /// GET and deserialize a JSON body.
    pub async fn get_json<T: DeserializeOwned>(&self, source: &str, url: &str) -> Result<T> {
        self.limiters.until_ready(source).await;
        let resp = self.client.get(url).send().await?;
        let resp = resp.error_for_status()?;
        Ok(resp.json::<T>().await?)
    }

    /// GET raw bytes.
    pub async fn get_bytes(&self, source: &str, url: &str) -> Result<Vec<u8>> {
        self.limiters.until_ready(source).await;
        let resp = self.client.get(url).send().await?;
        let resp = resp.error_for_status()?;
        Ok(resp.bytes().await?.to_vec())
    }

    /// GET with extra headers (e.g. an `Authorization` or vendor key header).
    pub async fn get_json_with_headers<T: DeserializeOwned>(
        &self,
        source: &str,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<T> {
        self.limiters.until_ready(source).await;
        let mut req = self.client.get(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = req.send().await?.error_for_status()?;
        Ok(resp.json::<T>().await?)
    }

    /// POST a JSON body and deserialize the JSON response.
    pub async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        source: &str,
        url: &str,
        body: &B,
    ) -> Result<T> {
        self.limiters.until_ready(source).await;
        let resp = self
            .client
            .post(url)
            .json(body)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json::<T>().await?)
    }
}
