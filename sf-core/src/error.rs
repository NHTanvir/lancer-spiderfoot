//! Error types for the SpiderFoot core engine.

use thiserror::Error;

/// The crate-wide result alias used throughout `sf-core` and the module trait.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid target: {0}")]
    InvalidTarget(String),

    #[error("unknown event type: {0}")]
    UnknownEventType(String),

    #[error("module `{module}` setup failed: {reason}")]
    ModuleSetup { module: String, reason: String },

    #[error("module `{module}` requires an API key but none was configured")]
    MissingApiKey { module: String },

    #[error("scan was aborted")]
    Aborted,

    #[error("configuration error: {0}")]
    Config(String),

    #[error("persistence error: {0}")]
    Persist(String),

    #[error("http error: {0}")]
    Http(String),

    #[error("rate limit exceeded for source {0}")]
    RateLimited(String),

    #[error("serialization error: {0}")]
    Serde(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Http(e.to_string())
    }
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Error::Persist(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e.to_string())
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(e: serde_yaml::Error) -> Self {
        Error::Serde(e.to_string())
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error::Config(e.to_string())
    }
}
