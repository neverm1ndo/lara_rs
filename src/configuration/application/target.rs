use std::sync::Arc;

use encoding_rs::Encoding;
use thiserror::Error;

use crate::{
    configuration::domain::ConfigurationFilePolicy,
    shared::file_storage::{local::LocalFileStorage, path::RelativeStoragePath},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigurationAccessScope {
    Primary {
        configurator_directory: RelativeStoragePath,
    },
    Auxiliary,
}

impl ConfigurationAccessScope {
    pub fn requires_backup_preservation(&self) -> bool {
        matches!(self, Self::Primary { .. })
    }
}

/// Immutable, request-scoped filesystem capability and policy. Its storage
/// root is fixed at construction; callers only supply relative paths.
#[derive(Debug, Clone)]
pub struct ConfigurationTarget {
    instance_id: String,
    storage: LocalFileStorage,
    policy: ConfigurationFilePolicy,
    encoding: &'static Encoding,
    artifact_paths: Vec<RelativeStoragePath>,
    access_scope: ConfigurationAccessScope,
}

impl ConfigurationTarget {
    pub(crate) fn new(
        instance_id: String,
        storage: LocalFileStorage,
        policy: ConfigurationFilePolicy,
        encoding: &'static Encoding,
        artifact_paths: Vec<RelativeStoragePath>,
        access_scope: ConfigurationAccessScope,
    ) -> Self {
        Self {
            instance_id,
            storage,
            policy,
            encoding,
            artifact_paths,
            access_scope,
        }
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn storage(&self) -> &LocalFileStorage {
        &self.storage
    }

    pub fn policy(&self) -> &ConfigurationFilePolicy {
        &self.policy
    }

    pub fn encoding(&self) -> &'static Encoding {
        self.encoding
    }

    pub fn artifact_paths(&self) -> &[RelativeStoragePath] {
        &self.artifact_paths
    }

    pub fn access_scope(&self) -> &ConfigurationAccessScope {
        &self.access_scope
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationTargetError {
    #[error("configuration target was not found")]
    NotFound,
    #[error("configuration capability is unavailable for this instance")]
    CapabilityUnavailable,
}

/// Port implemented at the application composition boundary. The
/// configuration context does not depend on registry storage or systemd.
pub trait ConfigurationTargetResolver: Send + Sync {
    fn resolve(
        &self,
        instance_id: &str,
    ) -> Result<Arc<ConfigurationTarget>, ConfigurationTargetError>;
}
