use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use thiserror::Error;

use super::{
    mutation::{FileMutationOperation, FileMutationRequest, FileRevision, MutationId},
    path::RelativeStoragePath,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupRequirement {
    Disabled,
    Optional,
    Required,
}

impl BackupRequirement {
    pub const fn is_required(self) -> bool {
        matches!(self, Self::Required)
    }
}

/// State observed by the coordinator immediately before a destructive
/// mutation. A backup receipt and the eventual permit must refer to this exact
/// revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSnapshot {
    path: RelativeStoragePath,
    revision: FileRevision,
}

impl FileSnapshot {
    pub fn new(
        path: RelativeStoragePath,
        revision: FileRevision,
    ) -> Result<Self, InvalidMutationPermit> {
        if path.is_root() {
            return Err(InvalidMutationPermit::RootSnapshot);
        }

        Ok(Self { path, revision })
    }

    pub fn path(&self) -> &RelativeStoragePath {
        &self.path
    }

    pub fn revision(&self) -> &FileRevision {
        &self.revision
    }
}

/// Opaque proof that a backup provider preserved a particular file revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReceipt {
    mutation_id: MutationId,
    backup_id: String,
    source_revision: FileRevision,
    created_at: DateTime<Utc>,
}

impl BackupReceipt {
    pub fn new(
        mutation_id: MutationId,
        backup_id: impl Into<String>,
        source_revision: FileRevision,
        created_at: DateTime<Utc>,
    ) -> Result<Self, InvalidMutationPermit> {
        let backup_id = backup_id.into();
        if backup_id.trim().is_empty() || backup_id.trim() != backup_id {
            return Err(InvalidMutationPermit::BackupId);
        }

        Ok(Self {
            mutation_id,
            backup_id,
            source_revision,
            created_at,
        })
    }

    pub fn mutation_id(&self) -> MutationId {
        self.mutation_id
    }

    pub fn backup_id(&self) -> &str {
        &self.backup_id
    }

    pub fn source_revision(&self) -> &FileRevision {
        &self.source_revision
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

/// Authorization token for the execution phase of a file mutation.
///
/// It is deliberately impossible to construct a permit for a stale revision,
/// a different mutation, or a snapshot at another path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationPermit {
    mutation_id: MutationId,
    expected_revision: Option<FileRevision>,
    backup_receipt: Option<BackupReceipt>,
}

impl MutationPermit {
    pub fn new(
        request: &FileMutationRequest,
        current_file: Option<&FileSnapshot>,
        backup_receipt: Option<BackupReceipt>,
        requirement: BackupRequirement,
    ) -> Result<Self, InvalidMutationPermit> {
        validate_snapshot(request, current_file)?;

        if requirement.is_required() && backup_receipt.is_none() {
            return Err(InvalidMutationPermit::RequiredBackupMissing);
        }

        let expected_revision = current_file.map(|snapshot| snapshot.revision().clone());
        if let Some(receipt) = backup_receipt.as_ref() {
            if receipt.mutation_id() != request.mutation_id() {
                return Err(InvalidMutationPermit::ReceiptMutationMismatch);
            }
            if expected_revision.as_ref() != Some(receipt.source_revision()) {
                return Err(InvalidMutationPermit::ReceiptRevisionMismatch);
            }
        }

        Ok(Self {
            mutation_id: request.mutation_id(),
            expected_revision,
            backup_receipt,
        })
    }

    pub fn mutation_id(&self) -> MutationId {
        self.mutation_id
    }

    pub fn expected_revision(&self) -> Option<&FileRevision> {
        self.expected_revision.as_ref()
    }

    pub fn backup_receipt(&self) -> Option<&BackupReceipt> {
        self.backup_receipt.as_ref()
    }
}

fn validate_snapshot(
    request: &FileMutationRequest,
    current_file: Option<&FileSnapshot>,
) -> Result<(), InvalidMutationPermit> {
    match (request.operation().source(), current_file) {
        (None, None) => {}
        (None, Some(_)) => return Err(InvalidMutationPermit::UnexpectedSnapshot),
        (Some(_), None) => return Err(InvalidMutationPermit::MissingSnapshot),
        (Some(source), Some(snapshot)) if source != snapshot.path() => {
            return Err(InvalidMutationPermit::SnapshotPathMismatch);
        }
        (Some(_), Some(_)) => {}
    }

    if let (Some(requested), Some(snapshot)) = (
        request.operation().expected_revision(),
        current_file.map(FileSnapshot::revision),
    ) && requested != snapshot
    {
        return Err(InvalidMutationPermit::StaleRevision);
    }

    Ok(())
}

pub type BeforeMutationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<MutationPermit, BeforeFileMutationError>> + Send + 'a>>;

pub type ReadFileSnapshotFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, ReadFileSnapshotError>> + Send + 'a>>;

/// Capability-safe content access offered to a pre-mutation consumer. A
/// backups implementation can persist the exact source bytes without knowing
/// the configuration storage root or importing its infrastructure.
pub trait FileSnapshotSource: Send + Sync {
    fn read_verified<'a>(&'a self, snapshot: &'a FileSnapshot) -> ReadFileSnapshotFuture<'a>;
}

/// Describes what the mutation will do with the file content.
///
/// The replacement bytes are borrowed from the already validated mutation
/// payload. They are never transcoded or copied by the coordinator, so a
/// backup provider can calculate a diff against the exact bytes that will be
/// written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileContentMutation<'a> {
    Create(&'a [u8]),
    Replace(&'a [u8]),
    Preserve,
    Remove,
}

impl<'a> FileContentMutation<'a> {
    pub const fn replacement(self) -> Option<&'a [u8]> {
        match self {
            Self::Create(content) | Self::Replace(content) => Some(content),
            Self::Preserve | Self::Remove => None,
        }
    }
}

/// Capability-safe description of a mutation at the last point before it is
/// applied to the filesystem.
///
/// This is the shared cross-domain contract used by a future backups bounded
/// context. It exposes neither an absolute path nor a concrete storage
/// implementation. Existing content can only be read through the verified
/// snapshot capability.
pub struct FileMutationIntent<'a> {
    request: &'a FileMutationRequest,
    current_file: Option<&'a FileSnapshot>,
    snapshot_source: &'a dyn FileSnapshotSource,
    content: FileContentMutation<'a>,
    backup_requirement: BackupRequirement,
}

impl<'a> FileMutationIntent<'a> {
    pub(crate) fn new(
        request: &'a FileMutationRequest,
        current_file: Option<&'a FileSnapshot>,
        snapshot_source: &'a dyn FileSnapshotSource,
        replacement: Option<&'a [u8]>,
        backup_requirement: BackupRequirement,
    ) -> Self {
        let content = match request.operation() {
            FileMutationOperation::Create { .. } => FileContentMutation::Create(
                replacement.expect("validated create mutation has replacement content"),
            ),
            FileMutationOperation::Overwrite { .. } => FileContentMutation::Replace(
                replacement.expect("validated overwrite mutation has replacement content"),
            ),
            FileMutationOperation::Delete { .. } => FileContentMutation::Remove,
            FileMutationOperation::Rename { .. } => FileContentMutation::Preserve,
        };

        Self {
            request,
            current_file,
            snapshot_source,
            content,
            backup_requirement,
        }
    }

    pub const fn request(&self) -> &FileMutationRequest {
        self.request
    }

    pub const fn current_file(&self) -> Option<&FileSnapshot> {
        self.current_file
    }

    pub const fn content(&self) -> FileContentMutation<'a> {
        self.content
    }

    pub const fn backup_requirement(&self) -> BackupRequirement {
        self.backup_requirement
    }

    /// Reads the exact current bytes only if the observed revision is still
    /// valid. Create mutations return `Ok(None)` because no source exists.
    pub async fn read_current(&self) -> Result<Option<Vec<u8>>, ReadFileSnapshotError> {
        match self.current_file {
            Some(snapshot) => self.snapshot_source.read_verified(snapshot).await.map(Some),
            None => Ok(None),
        }
    }
}

/// Synchronous-in-the-workflow guard invoked before a filesystem mutation.
/// Implementations may persist a backup and must not return until it is safe to
/// continue.
pub trait BeforeFileMutation: Send + Sync {
    fn prepare<'a>(&'a self, intent: FileMutationIntent<'a>) -> BeforeMutationFuture<'a>;
}

/// Explicit fallback used before a backup provider is configured. It never
/// silently bypasses a required backup.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoBackupProvider;

impl BeforeFileMutation for NoBackupProvider {
    fn prepare<'a>(&'a self, intent: FileMutationIntent<'a>) -> BeforeMutationFuture<'a> {
        Box::pin(async move {
            if intent.backup_requirement().is_required() {
                return Err(BeforeFileMutationError::RequiredBackupUnavailable);
            }

            MutationPermit::new(
                intent.request(),
                intent.current_file(),
                None,
                intent.backup_requirement(),
            )
            .map_err(Into::into)
        })
    }
}

#[derive(Debug, Error)]
pub enum BeforeFileMutationError {
    #[error("a required file backup provider is unavailable")]
    RequiredBackupUnavailable,
    #[error("file mutation was rejected by its pre-mutation guard: {reason}")]
    Rejected { reason: String },
    #[error("file mutation guard is unavailable: {message}")]
    Unavailable { message: String },
    #[error(transparent)]
    InvalidPermit(#[from] InvalidMutationPermit),
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ReadFileSnapshotError {
    #[error("file changed while its snapshot was being read")]
    Changed,
    #[error("file snapshot exceeds the storage read limit")]
    ContentTooLarge,
    #[error("file snapshot source is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidMutationPermit {
    #[error("a file snapshot cannot refer to the storage root")]
    RootSnapshot,
    #[error("backup identifier must be non-empty and trimmed")]
    BackupId,
    #[error("create mutations must not have a current-file snapshot")]
    UnexpectedSnapshot,
    #[error("destructive mutations require a current-file snapshot")]
    MissingSnapshot,
    #[error("current-file snapshot path does not match the mutation source")]
    SnapshotPathMismatch,
    #[error("current-file revision differs from the requested revision")]
    StaleRevision,
    #[error("backup receipt belongs to another mutation")]
    ReceiptMutationMismatch,
    #[error("mutation permit belongs to another mutation")]
    PermitMutationMismatch,
    #[error("backup receipt belongs to another file revision")]
    ReceiptRevisionMismatch,
    #[error("a required backup receipt is missing")]
    RequiredBackupMissing,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::shared::file_storage::mutation::{
        FileMutationOperation, MutationActor, StorageNamespace,
    };

    fn namespace() -> StorageNamespace {
        StorageNamespace::new("configuration").unwrap()
    }

    fn actor() -> MutationActor {
        MutationActor::new("42", Some("session-1".into())).unwrap()
    }

    fn path(value: &str) -> RelativeStoragePath {
        RelativeStoragePath::new(value).unwrap()
    }

    fn revision(timestamp: i64) -> FileRevision {
        FileRevision::from_metadata(128, Utc.timestamp_opt(timestamp, 0).unwrap())
    }

    fn delete_request(expected_revision: Option<FileRevision>) -> FileMutationRequest {
        FileMutationRequest::new(
            MutationId::new(),
            namespace(),
            actor(),
            Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
            FileMutationOperation::Delete {
                path: path("server.cfg"),
                expected_revision,
            },
        )
        .unwrap()
    }

    struct UnusedSnapshotSource;

    impl FileSnapshotSource for UnusedSnapshotSource {
        fn read_verified<'a>(&'a self, _snapshot: &'a FileSnapshot) -> ReadFileSnapshotFuture<'a> {
            Box::pin(async { Err(ReadFileSnapshotError::Unavailable) })
        }
    }

    #[test]
    fn snapshot_rejects_the_capability_root() {
        assert_eq!(
            FileSnapshot::new(RelativeStoragePath::root(), revision(1_700_000_000)),
            Err(InvalidMutationPermit::RootSnapshot)
        );
    }

    #[test]
    fn receipt_is_bound_to_mutation_revision_and_creation_time() {
        let id = MutationId::new();
        let source_revision = revision(1_700_000_000);
        let created_at = Utc.timestamp_opt(1_700_000_050, 0).unwrap();
        let receipt =
            BackupReceipt::new(id, "backup-1", source_revision.clone(), created_at).unwrap();

        assert_eq!(receipt.mutation_id(), id);
        assert_eq!(receipt.backup_id(), "backup-1");
        assert_eq!(receipt.source_revision(), &source_revision);
        assert_eq!(receipt.created_at(), created_at);
        assert!(BackupReceipt::new(id, " ", source_revision, created_at).is_err());
    }

    #[test]
    fn permit_accepts_matching_snapshot_and_backup_receipt() {
        let source_revision = revision(1_700_000_000);
        let request = delete_request(Some(source_revision.clone()));
        let snapshot = FileSnapshot::new(path("server.cfg"), source_revision.clone()).unwrap();
        let receipt = BackupReceipt::new(
            request.mutation_id(),
            "backup-1",
            source_revision.clone(),
            Utc.timestamp_opt(1_700_000_050, 0).unwrap(),
        )
        .unwrap();

        let permit = MutationPermit::new(
            &request,
            Some(&snapshot),
            Some(receipt),
            BackupRequirement::Required,
        )
        .unwrap();

        assert_eq!(permit.mutation_id(), request.mutation_id());
        assert_eq!(permit.expected_revision(), Some(&source_revision));
        assert_eq!(permit.backup_receipt().unwrap().backup_id(), "backup-1");
    }

    #[test]
    fn create_permit_requires_no_snapshot_or_receipt() {
        let request = FileMutationRequest::create(namespace(), actor(), path("new.cfg")).unwrap();
        let permit =
            MutationPermit::new(&request, None, None, BackupRequirement::Disabled).unwrap();

        assert!(permit.expected_revision().is_none());
        assert!(permit.backup_receipt().is_none());

        let snapshot = FileSnapshot::new(path("new.cfg"), revision(1_700_000_000)).unwrap();
        assert_eq!(
            MutationPermit::new(&request, Some(&snapshot), None, BackupRequirement::Disabled),
            Err(InvalidMutationPermit::UnexpectedSnapshot)
        );
    }

    #[test]
    fn permit_rejects_missing_wrong_or_stale_snapshots() {
        let expected = revision(1_700_000_000);
        let request = delete_request(Some(expected));

        assert_eq!(
            MutationPermit::new(&request, None, None, BackupRequirement::Optional),
            Err(InvalidMutationPermit::MissingSnapshot)
        );

        let wrong_path = FileSnapshot::new(path("other.cfg"), revision(1_700_000_000)).unwrap();
        assert_eq!(
            MutationPermit::new(
                &request,
                Some(&wrong_path),
                None,
                BackupRequirement::Optional
            ),
            Err(InvalidMutationPermit::SnapshotPathMismatch)
        );

        let stale = FileSnapshot::new(path("server.cfg"), revision(1_700_000_001)).unwrap();
        assert_eq!(
            MutationPermit::new(&request, Some(&stale), None, BackupRequirement::Optional),
            Err(InvalidMutationPermit::StaleRevision)
        );
    }

    #[test]
    fn permit_rejects_receipts_for_another_mutation_or_revision() {
        let source_revision = revision(1_700_000_000);
        let request = delete_request(None);
        let snapshot = FileSnapshot::new(path("server.cfg"), source_revision.clone()).unwrap();
        let created_at = Utc.timestamp_opt(1_700_000_050, 0).unwrap();

        let wrong_mutation = BackupReceipt::new(
            MutationId::new(),
            "backup-1",
            source_revision.clone(),
            created_at,
        )
        .unwrap();
        assert_eq!(
            MutationPermit::new(
                &request,
                Some(&snapshot),
                Some(wrong_mutation),
                BackupRequirement::Required
            ),
            Err(InvalidMutationPermit::ReceiptMutationMismatch)
        );

        let wrong_revision = BackupReceipt::new(
            request.mutation_id(),
            "backup-2",
            revision(1_700_000_001),
            created_at,
        )
        .unwrap();
        assert_eq!(
            MutationPermit::new(
                &request,
                Some(&snapshot),
                Some(wrong_revision),
                BackupRequirement::Required
            ),
            Err(InvalidMutationPermit::ReceiptRevisionMismatch)
        );
    }

    #[test]
    fn required_policy_cannot_produce_a_permit_without_a_receipt() {
        let request = delete_request(None);
        let snapshot = FileSnapshot::new(path("server.cfg"), revision(1_700_000_000)).unwrap();

        assert_eq!(
            MutationPermit::new(&request, Some(&snapshot), None, BackupRequirement::Required),
            Err(InvalidMutationPermit::RequiredBackupMissing)
        );
    }

    #[tokio::test]
    async fn no_backup_provider_fails_closed_only_when_backup_is_required() {
        let request = delete_request(None);
        let snapshot = FileSnapshot::new(path("server.cfg"), revision(1_700_000_000)).unwrap();

        for requirement in [BackupRequirement::Disabled, BackupRequirement::Optional] {
            let intent = FileMutationIntent::new(
                &request,
                Some(&snapshot),
                &UnusedSnapshotSource,
                None,
                requirement,
            );
            let permit = NoBackupProvider.prepare(intent).await.unwrap();
            assert!(permit.backup_receipt().is_none());
        }

        let required = FileMutationIntent::new(
            &request,
            Some(&snapshot),
            &UnusedSnapshotSource,
            None,
            BackupRequirement::Required,
        );
        assert!(matches!(
            NoBackupProvider.prepare(required).await,
            Err(BeforeFileMutationError::RequiredBackupUnavailable)
        ));
    }

    #[tokio::test]
    async fn mutation_intent_exposes_opaque_replacement_and_verified_current_bytes() {
        struct SnapshotSource;

        impl FileSnapshotSource for SnapshotSource {
            fn read_verified<'a>(
                &'a self,
                _snapshot: &'a FileSnapshot,
            ) -> ReadFileSnapshotFuture<'a> {
                Box::pin(async { Ok(vec![0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2]) })
            }
        }

        let request =
            FileMutationRequest::overwrite(namespace(), actor(), path("server.cfg"), None).unwrap();
        let snapshot = FileSnapshot::new(path("server.cfg"), revision(1_700_000_000)).unwrap();
        let replacement = [0xd2, 0xe5, 0xf1, 0xf2];
        let intent = FileMutationIntent::new(
            &request,
            Some(&snapshot),
            &SnapshotSource,
            Some(&replacement),
            BackupRequirement::Required,
        );

        assert_eq!(intent.content(), FileContentMutation::Replace(&replacement));
        assert_eq!(intent.content().replacement(), Some(replacement.as_slice()));
        assert_eq!(
            intent.read_current().await.unwrap(),
            Some(vec![0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2])
        );
        assert_eq!(intent.request().namespace().as_str(), "configuration");
        assert_eq!(intent.backup_requirement(), BackupRequirement::Required);
    }

    #[test]
    fn backup_requirement_reports_only_required_policy_as_mandatory() {
        assert!(!BackupRequirement::Disabled.is_required());
        assert!(!BackupRequirement::Optional.is_required());
        assert!(BackupRequirement::Required.is_required());
    }
}
