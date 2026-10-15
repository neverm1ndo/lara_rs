use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use super::path::RelativeStoragePath;

/// Stable identifier shared by the prepare, backup, mutation and event stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MutationId(Uuid);

impl MutationId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for MutationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MutationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for MutationId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

/// Identifies the bounded context that owns the file operation without making
/// the shared storage depend on that context.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StorageNamespace(String);

impl StorageNamespace {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidMutationModel> {
        let value = value.into();
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(InvalidMutationModel::Namespace);
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StorageNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Authentication-neutral description of who initiated a mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationActor {
    subject: String,
    session: Option<String>,
}

impl MutationActor {
    pub fn new(
        subject: impl Into<String>,
        session: Option<String>,
    ) -> Result<Self, InvalidMutationModel> {
        let subject = subject.into();
        if subject.trim().is_empty() || subject.trim() != subject {
            return Err(InvalidMutationModel::ActorSubject);
        }

        if session
            .as_ref()
            .is_some_and(|value| value.trim().is_empty() || value.trim() != value)
        {
            return Err(InvalidMutationModel::ActorSession);
        }

        Ok(Self { subject, session })
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn session(&self) -> Option<&str> {
        self.session.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentHashAlgorithm {
    Blake3,
    Sha256,
}

impl ContentHashAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
            Self::Sha256 => "sha256",
        }
    }

    const fn hex_length(self) -> usize {
        match self {
            Self::Blake3 | Self::Sha256 => 64,
        }
    }
}

/// Content digest used for optimistic concurrency and backup verification.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileContentHash {
    algorithm: ContentHashAlgorithm,
    hex_digest: String,
}

impl FileContentHash {
    pub fn new(
        algorithm: ContentHashAlgorithm,
        hex_digest: impl Into<String>,
    ) -> Result<Self, InvalidMutationModel> {
        let hex_digest = hex_digest.into();
        if hex_digest.len() != algorithm.hex_length()
            || !hex_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(InvalidMutationModel::ContentHash);
        }

        Ok(Self {
            algorithm,
            hex_digest: hex_digest.to_ascii_lowercase(),
        })
    }

    pub fn algorithm(&self) -> ContentHashAlgorithm {
        self.algorithm
    }

    pub fn hex_digest(&self) -> &str {
        &self.hex_digest
    }
}

impl fmt::Display for FileContentHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.algorithm.as_str(), self.hex_digest)
    }
}

/// Observable state of a file at one point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRevision {
    size: u64,
    modified_at: DateTime<Utc>,
    content_hash: Option<FileContentHash>,
}

impl FileRevision {
    pub fn new(
        size: u64,
        modified_at: DateTime<Utc>,
        content_hash: Option<FileContentHash>,
    ) -> Self {
        Self {
            size,
            modified_at,
            content_hash,
        }
    }

    pub fn from_metadata(size: u64, modified_at: DateTime<Utc>) -> Self {
        Self::new(size, modified_at, None)
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn modified_at(&self) -> DateTime<Utc> {
        self.modified_at
    }

    pub fn content_hash(&self) -> Option<&FileContentHash> {
        self.content_hash.as_ref()
    }

    pub fn with_content_hash(mut self, content_hash: FileContentHash) -> Self {
        self.content_hash = Some(content_hash);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileMutationKind {
    Create,
    Overwrite,
    Delete,
    Rename,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileMutationOperation {
    Create {
        path: RelativeStoragePath,
    },
    Overwrite {
        path: RelativeStoragePath,
        expected_revision: Option<FileRevision>,
    },
    Delete {
        path: RelativeStoragePath,
        expected_revision: Option<FileRevision>,
    },
    Rename {
        source: RelativeStoragePath,
        destination: RelativeStoragePath,
        expected_revision: Option<FileRevision>,
    },
}

impl FileMutationOperation {
    pub const fn kind(&self) -> FileMutationKind {
        match self {
            Self::Create { .. } => FileMutationKind::Create,
            Self::Overwrite { .. } => FileMutationKind::Overwrite,
            Self::Delete { .. } => FileMutationKind::Delete,
            Self::Rename { .. } => FileMutationKind::Rename,
        }
    }

    pub fn source(&self) -> Option<&RelativeStoragePath> {
        match self {
            Self::Create { .. } => None,
            Self::Overwrite { path, .. } | Self::Delete { path, .. } => Some(path),
            Self::Rename { source, .. } => Some(source),
        }
    }

    pub fn destination(&self) -> Option<&RelativeStoragePath> {
        match self {
            Self::Create { path } => Some(path),
            Self::Overwrite { path, .. } => Some(path),
            Self::Delete { .. } => None,
            Self::Rename { destination, .. } => Some(destination),
        }
    }

    pub fn expected_revision(&self) -> Option<&FileRevision> {
        match self {
            Self::Create { .. } => None,
            Self::Overwrite {
                expected_revision, ..
            }
            | Self::Delete {
                expected_revision, ..
            }
            | Self::Rename {
                expected_revision, ..
            } => expected_revision.as_ref(),
        }
    }
}

/// Validated command passed through the future mutation coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMutationRequest {
    mutation_id: MutationId,
    namespace: StorageNamespace,
    actor: MutationActor,
    requested_at: DateTime<Utc>,
    operation: FileMutationOperation,
}

impl FileMutationRequest {
    pub fn new(
        mutation_id: MutationId,
        namespace: StorageNamespace,
        actor: MutationActor,
        requested_at: DateTime<Utc>,
        operation: FileMutationOperation,
    ) -> Result<Self, InvalidMutationModel> {
        validate_operation(&operation)?;

        Ok(Self {
            mutation_id,
            namespace,
            actor,
            requested_at,
            operation,
        })
    }

    pub fn create(
        namespace: StorageNamespace,
        actor: MutationActor,
        path: RelativeStoragePath,
    ) -> Result<Self, InvalidMutationModel> {
        Self::generated(namespace, actor, FileMutationOperation::Create { path })
    }

    pub fn overwrite(
        namespace: StorageNamespace,
        actor: MutationActor,
        path: RelativeStoragePath,
        expected_revision: Option<FileRevision>,
    ) -> Result<Self, InvalidMutationModel> {
        Self::generated(
            namespace,
            actor,
            FileMutationOperation::Overwrite {
                path,
                expected_revision,
            },
        )
    }

    pub fn delete(
        namespace: StorageNamespace,
        actor: MutationActor,
        path: RelativeStoragePath,
        expected_revision: Option<FileRevision>,
    ) -> Result<Self, InvalidMutationModel> {
        Self::generated(
            namespace,
            actor,
            FileMutationOperation::Delete {
                path,
                expected_revision,
            },
        )
    }

    pub fn rename(
        namespace: StorageNamespace,
        actor: MutationActor,
        source: RelativeStoragePath,
        destination: RelativeStoragePath,
        expected_revision: Option<FileRevision>,
    ) -> Result<Self, InvalidMutationModel> {
        Self::generated(
            namespace,
            actor,
            FileMutationOperation::Rename {
                source,
                destination,
                expected_revision,
            },
        )
    }

    fn generated(
        namespace: StorageNamespace,
        actor: MutationActor,
        operation: FileMutationOperation,
    ) -> Result<Self, InvalidMutationModel> {
        Self::new(MutationId::new(), namespace, actor, Utc::now(), operation)
    }

    pub fn mutation_id(&self) -> MutationId {
        self.mutation_id
    }

    pub fn namespace(&self) -> &StorageNamespace {
        &self.namespace
    }

    pub fn actor(&self) -> &MutationActor {
        &self.actor
    }

    pub fn requested_at(&self) -> DateTime<Utc> {
        self.requested_at
    }

    pub fn operation(&self) -> &FileMutationOperation {
        &self.operation
    }
}

fn validate_operation(operation: &FileMutationOperation) -> Result<(), InvalidMutationModel> {
    if operation.source().is_some_and(RelativeStoragePath::is_root)
        || operation
            .destination()
            .is_some_and(RelativeStoragePath::is_root)
    {
        return Err(InvalidMutationModel::RootMutation);
    }

    if let FileMutationOperation::Rename {
        source,
        destination,
        ..
    } = operation
        && source == destination
    {
        return Err(InvalidMutationModel::RenameToSelf);
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidMutationModel {
    #[error("storage namespace must use lowercase ASCII letters, digits or hyphens")]
    Namespace,
    #[error("mutation actor subject must not be empty")]
    ActorSubject,
    #[error("mutation actor session must not be empty when present")]
    ActorSession,
    #[error("content hash must be a hexadecimal digest of the required length")]
    ContentHash,
    #[error("the storage capability root cannot be mutated")]
    RootMutation,
    #[error("a file cannot be renamed to the same path")]
    RenameToSelf,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn namespace() -> StorageNamespace {
        StorageNamespace::new("configuration").unwrap()
    }

    fn actor() -> MutationActor {
        MutationActor::new("42", Some("session-1".into())).unwrap()
    }

    fn path(value: &str) -> RelativeStoragePath {
        RelativeStoragePath::new(value).unwrap()
    }

    fn revision() -> FileRevision {
        FileRevision::from_metadata(128, Utc.timestamp_opt(1_700_000_000, 0).unwrap())
    }

    #[test]
    fn mutation_id_round_trips_as_uuid() {
        let id = MutationId::new();
        let parsed: MutationId = id.to_string().parse().unwrap();

        assert_eq!(parsed, id);
        assert_eq!(MutationId::from_uuid(id.as_uuid()), id);
    }

    #[test]
    fn validates_namespace_and_actor_without_auth_dependency() {
        assert_eq!(namespace().as_str(), "configuration");
        assert_eq!(actor().subject(), "42");
        assert_eq!(actor().session(), Some("session-1"));

        for invalid in ["", "Configuration", "configuration_files", "maps/files"] {
            assert!(StorageNamespace::new(invalid).is_err());
        }
        assert!(MutationActor::new(" ", None).is_err());
        assert!(MutationActor::new(" 42", None).is_err());
        assert!(MutationActor::new("42", Some(" ".into())).is_err());
    }

    #[test]
    fn validates_and_normalizes_content_hashes() {
        let uppercase = "AB".repeat(32);
        let hash = FileContentHash::new(ContentHashAlgorithm::Blake3, uppercase).unwrap();

        assert_eq!(hash.algorithm(), ContentHashAlgorithm::Blake3);
        assert_eq!(hash.hex_digest(), "ab".repeat(32));
        assert_eq!(hash.to_string(), format!("blake3:{}", "ab".repeat(32)));
        assert!(FileContentHash::new(ContentHashAlgorithm::Sha256, "short").is_err());
        assert!(FileContentHash::new(ContentHashAlgorithm::Sha256, "zz".repeat(32)).is_err());
    }

    #[test]
    fn models_revision_with_optional_strong_hash() {
        let base = revision();
        assert_eq!(base.size(), 128);
        assert_eq!(base.modified_at().timestamp(), 1_700_000_000);
        assert!(base.content_hash().is_none());

        let hash = FileContentHash::new(ContentHashAlgorithm::Sha256, "12".repeat(32)).unwrap();
        let strong = base.with_content_hash(hash.clone());
        assert_eq!(strong.content_hash(), Some(&hash));
    }

    #[test]
    fn exposes_operation_paths_kind_and_expected_revision() {
        let expected = revision();
        let operation = FileMutationOperation::Rename {
            source: path("server.cfg"),
            destination: path("server-old.cfg"),
            expected_revision: Some(expected.clone()),
        };

        assert_eq!(operation.kind(), FileMutationKind::Rename);
        assert_eq!(operation.source(), Some(&path("server.cfg")));
        assert_eq!(operation.destination(), Some(&path("server-old.cfg")));
        assert_eq!(operation.expected_revision(), Some(&expected));
    }

    #[test]
    fn rejects_root_mutations_and_rename_to_self() {
        let requested_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let build = |operation| {
            FileMutationRequest::new(
                MutationId::new(),
                namespace(),
                actor(),
                requested_at,
                operation,
            )
        };

        assert_eq!(
            build(FileMutationOperation::Delete {
                path: RelativeStoragePath::root(),
                expected_revision: None,
            }),
            Err(InvalidMutationModel::RootMutation)
        );
        assert_eq!(
            build(FileMutationOperation::Rename {
                source: path("server.cfg"),
                destination: path("server.cfg"),
                expected_revision: None,
            }),
            Err(InvalidMutationModel::RenameToSelf)
        );
    }

    #[test]
    fn builds_a_valid_create_request_with_generated_identity() {
        let request =
            FileMutationRequest::create(namespace(), actor(), path("server.cfg")).unwrap();

        assert_eq!(request.namespace().as_str(), "configuration");
        assert_eq!(request.actor().subject(), "42");
        assert_eq!(request.operation().kind(), FileMutationKind::Create);
        assert!(request.requested_at() <= Utc::now());
        assert_eq!(request.mutation_id().to_string().len(), 36);
    }

    #[test]
    fn factories_build_each_destructive_operation() {
        let expected = revision();
        let overwrite = FileMutationRequest::overwrite(
            namespace(),
            actor(),
            path("server.cfg"),
            Some(expected.clone()),
        )
        .unwrap();
        let delete = FileMutationRequest::delete(
            namespace(),
            actor(),
            path("server.cfg"),
            Some(expected.clone()),
        )
        .unwrap();
        let rename = FileMutationRequest::rename(
            namespace(),
            actor(),
            path("server.cfg"),
            path("server-old.cfg"),
            Some(expected.clone()),
        )
        .unwrap();

        assert_eq!(overwrite.operation().kind(), FileMutationKind::Overwrite);
        assert_eq!(delete.operation().kind(), FileMutationKind::Delete);
        assert_eq!(rename.operation().kind(), FileMutationKind::Rename);
        assert_eq!(rename.operation().expected_revision(), Some(&expected));
    }
}
