use std::{future::Future, io, pin::Pin};

use chrono::{DateTime, Utc};
use encoding_rs::{Encoding, WINDOWS_1251};
use thiserror::Error;
use tokio::io::AsyncRead;

use crate::{
    configuration::domain::{ConfigurationAccess, ConfigurationFileChanged, ConfigurationFileKind},
    shared::file_storage::{mutation::MutationActor, path::RelativeStoragePath},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationRequestContext {
    access: ConfigurationAccess,
    actor: MutationActor,
}

impl ConfigurationRequestContext {
    pub fn new(access: ConfigurationAccess, actor: MutationActor) -> Self {
        Self { access, actor }
    }

    pub fn access(&self) -> &ConfigurationAccess {
        &self.access
    }

    pub fn actor(&self) -> &MutationActor {
        &self.actor
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationTreeEntryKind {
    Directory,
    Text,
    Binary,
}

impl From<ConfigurationFileKind> for ConfigurationTreeEntryKind {
    fn from(kind: ConfigurationFileKind) -> Self {
        match kind {
            ConfigurationFileKind::Text => Self::Text,
            ConfigurationFileKind::Binary => Self::Binary,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationTreeEntry {
    pub path: RelativeStoragePath,
    pub name: String,
    pub kind: ConfigurationTreeEntryKind,
    pub size: Option<u64>,
    pub modified_at: Option<DateTime<Utc>>,
    pub children: Vec<ConfigurationTreeEntry>,
}

pub struct ConfigurationTextFile {
    pub reader: Pin<Box<dyn AsyncRead + Send>>,
    pub content_length: Option<u64>,
    pub file_name: String,
    /// WHATWG encoding label exposed in the HTTP Content-Type header. The
    /// stream itself is not transcoded by the backend.
    pub encoding_label: String,
}

/// Bytes accepted at the HTTP boundary after validating them against the
/// server-configured legacy encoding. Validation never changes the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationFileContent(Vec<u8>);

impl ConfigurationFileContent {
    pub fn validate(
        bytes: Vec<u8>,
        encoding: &'static Encoding,
    ) -> Result<Self, ConfigurationFileServiceError> {
        // Windows-1251 is a single-byte encoding, so validation requires no
        // decoding. 0x98 is the sole unassigned byte in the Windows code page;
        // WHATWG maps it permissively and therefore encoding_rs does not flag it.
        if std::ptr::eq(encoding, WINDOWS_1251) {
            return if bytes.contains(&0x98) {
                Err(ConfigurationFileServiceError::InvalidEncoding)
            } else {
                Ok(Self(bytes))
            };
        }

        let (_, had_errors) = encoding.decode_without_bom_handling(&bytes);
        if had_errors {
            return Err(ConfigurationFileServiceError::InvalidEncoding);
        }

        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

pub type ConfigurationServiceFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ConfigurationFileServiceError>> + Send + 'a>>;

/// Application boundary consumed by HTTP handlers. Its implementation owns
/// filesystem policy and mutation/event orchestration; upload bytes have
/// already passed encoding validation and remain otherwise untouched.
pub trait ConfigurationFileService: Send + Sync {
    fn tree<'a>(
        &'a self,
        context: ConfigurationRequestContext,
    ) -> ConfigurationServiceFuture<'a, Vec<ConfigurationTreeEntry>>;

    fn open_text<'a>(
        &'a self,
        context: ConfigurationRequestContext,
        path: RelativeStoragePath,
    ) -> ConfigurationServiceFuture<'a, ConfigurationTextFile>;

    fn create<'a>(
        &'a self,
        context: ConfigurationRequestContext,
        path: RelativeStoragePath,
        content: ConfigurationFileContent,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged>;

    fn overwrite<'a>(
        &'a self,
        context: ConfigurationRequestContext,
        path: RelativeStoragePath,
        content: ConfigurationFileContent,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged>;

    fn delete<'a>(
        &'a self,
        context: ConfigurationRequestContext,
        path: RelativeStoragePath,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged>;

    fn rename<'a>(
        &'a self,
        context: ConfigurationRequestContext,
        source: RelativeStoragePath,
        destination: RelativeStoragePath,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged>;
}

#[derive(Debug, Error)]
pub enum ConfigurationFileServiceError {
    #[error("configuration path was not found")]
    NotFound,
    #[error("configuration destination already exists")]
    AlreadyExists,
    #[error("configuration file changed concurrently")]
    Conflict,
    #[error("the requested file is binary")]
    BinaryFile,
    #[error("configuration content is not valid in the configured encoding")]
    InvalidEncoding,
    #[error("configuration content exceeds the allowed size")]
    ContentTooLarge,
    #[error("configuration file service is unavailable")]
    Unavailable,
    #[error("configuration stream failed")]
    Stream(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use encoding_rs::{UTF_8, WINDOWS_1251};

    use super::*;

    #[test]
    fn validates_without_transcoding_windows_1251_bytes() {
        let bytes = vec![0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2];
        let content = ConfigurationFileContent::validate(bytes.clone(), WINDOWS_1251).unwrap();

        assert_eq!(content.as_bytes(), bytes);
        assert_eq!(content.into_bytes(), bytes);
    }

    #[test]
    fn rejects_bytes_invalid_for_the_configured_encoding() {
        assert!(matches!(
            ConfigurationFileContent::validate(vec![0xff], UTF_8),
            Err(ConfigurationFileServiceError::InvalidEncoding)
        ));
        assert!(matches!(
            ConfigurationFileContent::validate(vec![0x98], WINDOWS_1251),
            Err(ConfigurationFileServiceError::InvalidEncoding)
        ));
    }
}
