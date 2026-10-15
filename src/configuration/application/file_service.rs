use std::{future::Future, io, pin::Pin};

use chrono::{DateTime, Utc};
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
}

pub type ConfigurationServiceFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ConfigurationFileServiceError>> + Send + 'a>>;

/// Application boundary consumed by HTTP handlers. Its implementation owns
/// filesystem policy, decoding and mutation/event orchestration.
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
        content: String,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged>;

    fn overwrite<'a>(
        &'a self,
        context: ConfigurationRequestContext,
        path: RelativeStoragePath,
        content: String,
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
    #[error("configuration content exceeds the allowed size")]
    ContentTooLarge,
    #[error("configuration file service is unavailable")]
    Unavailable,
    #[error("configuration stream failed")]
    Stream(#[from] io::Error),
}
