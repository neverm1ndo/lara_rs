use std::{future::Future, pin::Pin, sync::Arc};

use thiserror::Error;

use crate::{
    configuration::{
        application::{
            file_service::{
                ConfigurationFileContent, ConfigurationTextFile, ConfigurationTreeEntry,
            },
            target::{
                ConfigurationAccessScope, ConfigurationTarget, ConfigurationTargetError,
                ConfigurationTargetResolver,
            },
        },
        domain::{ConfigurationAccess, ConfigurationFileChanged},
    },
    shared::{
        file_storage::{
            mutation::{
                ContentHashAlgorithm, FileContentHash, FileRevision, MutationActor, MutationId,
            },
            path::RelativeStoragePath,
        },
        user_role::UserRole,
    },
};

/// A strong content tag. The HTTP boundary serializes it with double quotes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationEntityTag(FileContentHash);

impl ConfigurationEntityTag {
    pub fn from_revision(revision: &FileRevision) -> Option<Self> {
        revision.content_hash().cloned().map(Self)
    }

    pub fn parse(value: &str) -> Result<Self, InvalidConfigurationEntityTag> {
        let inner = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .ok_or(InvalidConfigurationEntityTag)?;
        let digest = inner
            .strip_prefix("sha256:")
            .ok_or(InvalidConfigurationEntityTag)?;
        let hash = FileContentHash::new(ContentHashAlgorithm::Sha256, digest)
            .map_err(|_| InvalidConfigurationEntityTag)?;
        Ok(Self(hash))
    }

    pub fn header_value(&self) -> String {
        format!("\"{}\"", self.0)
    }

    pub fn matches(&self, revision: &FileRevision) -> bool {
        revision.content_hash() == Some(&self.0)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("expected one strong SHA-256 entity tag")]
pub struct InvalidConfigurationEntityTag;

#[derive(Clone)]
pub struct InstanceConfigurationRequest {
    target: Arc<ConfigurationTarget>,
    access: ConfigurationAccess,
    actor: MutationActor,
    mutation_id: Option<MutationId>,
}

impl InstanceConfigurationRequest {
    pub fn authorize(
        resolver: &dyn ConfigurationTargetResolver,
        instance_id: &str,
        main_group: UserRole,
        permissions: &[UserRole],
        actor: MutationActor,
    ) -> Result<Self, InstanceConfigurationError> {
        let target = resolver.resolve(instance_id).map_err(|error| match error {
            ConfigurationTargetError::NotFound
            | ConfigurationTargetError::CapabilityUnavailable => {
                InstanceConfigurationError::NotFound
            }
        })?;
        let has_developer =
            main_group == UserRole::Developer || permissions.contains(&UserRole::Developer);
        let access = match target.access_scope() {
            ConfigurationAccessScope::Primary {
                configurator_directory,
            } => ConfigurationAccess::authorize(main_group, permissions, configurator_directory)
                .map_err(|_| InstanceConfigurationError::Forbidden)?,
            ConfigurationAccessScope::Auxiliary if has_developer => ConfigurationAccess::authorize(
                main_group,
                permissions,
                &RelativeStoragePath::root(),
            )
            .map_err(|_| InstanceConfigurationError::NotFound)?,
            ConfigurationAccessScope::Auxiliary => {
                return Err(InstanceConfigurationError::NotFound);
            }
        };
        Ok(Self {
            target,
            access,
            actor,
            mutation_id: None,
        })
    }

    pub fn target(&self) -> &ConfigurationTarget {
        &self.target
    }

    pub fn access(&self) -> &ConfigurationAccess {
        &self.access
    }

    pub fn actor(&self) -> &MutationActor {
        &self.actor
    }

    pub fn with_mutation_id(mut self, mutation_id: MutationId) -> Self {
        self.mutation_id = Some(mutation_id);
        self
    }

    pub fn mutation_id(&self) -> Option<MutationId> {
        self.mutation_id
    }

    pub fn validate_content(
        &self,
        bytes: Vec<u8>,
    ) -> Result<ConfigurationFileContent, InstanceConfigurationError> {
        if bytes.len() as u64 > self.target.storage().limits().max_stream_size_bytes {
            return Err(InstanceConfigurationError::ContentTooLarge);
        }
        ConfigurationFileContent::validate(bytes, self.target.encoding())
            .map_err(|_| InstanceConfigurationError::InvalidEncoding)
    }
}

pub struct InstanceConfigurationTextFile {
    pub file: ConfigurationTextFile,
    pub etag: ConfigurationEntityTag,
}

pub struct InstanceConfigurationMutation {
    pub instance_id: String,
    pub resource_kind: ConfigurationResourceKind,
    pub event: ConfigurationFileChanged,
    pub etag: Option<ConfigurationEntityTag>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationResourceKind {
    TextFile,
    Artifact,
}

pub type InstanceConfigurationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, InstanceConfigurationError>> + Send + 'a>>;

#[derive(Debug, Error)]
pub enum InstanceConfigurationError {
    #[error("configuration target or file was not found")]
    NotFound,
    #[error("configuration access is forbidden")]
    Forbidden,
    #[error("configuration destination already exists")]
    AlreadyExists,
    #[error("configuration destination conflicts with another mutation")]
    Conflict,
    #[error("configuration precondition failed")]
    PreconditionFailed,
    #[error("the requested file is binary")]
    BinaryFile,
    #[error("configuration content is invalid for this instance encoding")]
    InvalidEncoding,
    #[error("configuration content exceeds the instance limit")]
    ContentTooLarge,
    #[error("configuration service is unavailable")]
    Unavailable,
}

pub trait InstanceConfigurationTextService: Send + Sync {
    fn tree<'a>(
        &'a self,
        context: InstanceConfigurationRequest,
    ) -> InstanceConfigurationFuture<'a, Vec<ConfigurationTreeEntry>>;

    fn open_text<'a>(
        &'a self,
        context: InstanceConfigurationRequest,
        path: RelativeStoragePath,
    ) -> InstanceConfigurationFuture<'a, InstanceConfigurationTextFile>;

    fn create<'a>(
        &'a self,
        context: InstanceConfigurationRequest,
        path: RelativeStoragePath,
        content: ConfigurationFileContent,
    ) -> InstanceConfigurationFuture<'a, InstanceConfigurationMutation>;

    fn overwrite<'a>(
        &'a self,
        context: InstanceConfigurationRequest,
        path: RelativeStoragePath,
        content: ConfigurationFileContent,
        expected: ConfigurationEntityTag,
    ) -> InstanceConfigurationFuture<'a, InstanceConfigurationMutation>;

    fn delete<'a>(
        &'a self,
        context: InstanceConfigurationRequest,
        path: RelativeStoragePath,
        expected: ConfigurationEntityTag,
    ) -> InstanceConfigurationFuture<'a, InstanceConfigurationMutation>;

    fn rename<'a>(
        &'a self,
        context: InstanceConfigurationRequest,
        source: RelativeStoragePath,
        destination: RelativeStoragePath,
        expected: ConfigurationEntityTag,
    ) -> InstanceConfigurationFuture<'a, InstanceConfigurationMutation>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_one_strong_sha256_tag() {
        let hash = FileContentHash::new(ContentHashAlgorithm::Sha256, "a".repeat(64)).unwrap();
        let revision = FileRevision::new(1, chrono::Utc::now(), Some(hash));
        let tag = ConfigurationEntityTag::from_revision(&revision).unwrap();
        assert_eq!(tag.header_value(), format!("\"sha256:{}\"", "a".repeat(64)));
        assert!(
            ConfigurationEntityTag::parse(&tag.header_value())
                .unwrap()
                .matches(&revision)
        );
        for invalid in [
            "W/\"sha256:abc\"",
            "*",
            "\"sha256:abc\"",
            "\"sha256:abc\", \"sha256:def\"",
        ] {
            assert!(ConfigurationEntityTag::parse(invalid).is_err());
        }
    }
}
