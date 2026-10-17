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
    #[error(
        "MFA encryption key must contain exactly {expected_bytes} bytes encoded as hexadecimal"
    )]
    InvalidMfaEncryptionKey { expected_bytes: usize },
    #[error("MFA TOTP digits must be either 6 or 8")]
    InvalidMfaTotpDigits,
    #[error("configuration value `{key}` must be between {minimum} and {maximum}")]
    ValueOutOfRange {
        key: &'static str,
        minimum: u64,
        maximum: u64,
    },
    #[error("configuration path `{key}` must be a non-empty relative path without traversal")]
    InvalidRelativePath { key: &'static str },
    #[error("configuration file extension `{extension}` is invalid")]
    InvalidFileExtension { extension: String },
    #[error("configuration file extensions must not contain duplicates: `{extension}`")]
    DuplicateFileExtension { extension: String },
    #[error("configuration binary file name `{name}` is invalid")]
    InvalidFileName { name: String },
    #[error("configuration binary file names must not contain duplicates: `{name}`")]
    DuplicateFileName { name: String },
    #[error("configuration ignored paths must not contain duplicates: `{path}`")]
    DuplicateIgnoredPath { path: String },
    #[error("unsupported fallback text encoding `{encoding}`")]
    UnsupportedTextEncoding { encoding: String },
    #[error("backup storage directory must not be inside the managed game-server root")]
    BackupDirectoryInsideGameServerRoot,
    #[error(
        "backup compression level {level} is invalid for `{codec}`; expected {minimum}–{maximum}"
    )]
    InvalidBackupCompressionLevel {
        codec: &'static str,
        level: u32,
        minimum: u32,
        maximum: u32,
    },
    #[error("failed to resolve configured filesystem paths")]
    ResolvePath(#[source] std::io::Error),
}
