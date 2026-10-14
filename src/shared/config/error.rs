use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to load server configuration: {0}")]
    Load(#[from] ::config::ConfigError),
    #[error("configuration value `{key}` must not be empty")]
    EmptyValue { key: &'static str },
    #[error("JWT secret must contain at least {minimum} bytes")]
    JwtSecretTooShort { minimum: usize },
    #[error("JWT TTL must be an integer between 60 and 86400 seconds")]
    InvalidJwtTtl,
}
