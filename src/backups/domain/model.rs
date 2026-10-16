use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use crate::shared::file_storage::{
    content::FileContentKind,
    mutation::{FileContentHash, FileMutationKind, FileRevision, MutationId, StorageNamespace},
    path::RelativeStoragePath,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackupId(Uuid);

impl BackupId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for BackupId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for BackupId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for BackupId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

/// Authentication-neutral user identity copied from the authenticated
/// mutation actor. No username, avatar, role or other denormalized user data
/// is stored in the backup aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackupInitiatorId(i64);

impl BackupInitiatorId {
    pub fn new(value: i64) -> Result<Self, InvalidBackup> {
        (value > 0)
            .then_some(Self(value))
            .ok_or(InvalidBackup::InitiatorId)
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BackupVersion(u64);

impl BackupVersion {
    pub const fn initial() -> Self {
        Self(0)
    }

    pub const fn from_value(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, InvalidBackup> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(InvalidBackup::VersionOverflow)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSource {
    namespace: StorageNamespace,
    path: RelativeStoragePath,
}

impl BackupSource {
    pub fn new(
        namespace: StorageNamespace,
        path: RelativeStoragePath,
    ) -> Result<Self, InvalidBackup> {
        if path.is_root() {
            return Err(InvalidBackup::SourceRoot);
        }
        Ok(Self { namespace, path })
    }

    pub const fn namespace(&self) -> &StorageNamespace {
        &self.namespace
    }

    pub const fn path(&self) -> &RelativeStoragePath {
        &self.path
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupAction {
    Overwrite,
    Delete,
}

impl TryFrom<FileMutationKind> for BackupAction {
    type Error = InvalidBackup;

    fn try_from(value: FileMutationKind) -> Result<Self, Self::Error> {
        match value {
            FileMutationKind::Overwrite => Ok(Self::Overwrite),
            FileMutationKind::Delete => Ok(Self::Delete),
            FileMutationKind::Create | FileMutationKind::Rename => {
                Err(InvalidBackup::UnsupportedMutation)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotCompression {
    None,
    Gzip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSnapshot {
    source_revision: FileRevision,
    content_hash: FileContentHash,
    content_kind: FileContentKind,
    original_bytes: u64,
    stored_bytes: u64,
    compression: SnapshotCompression,
}

impl BackupSnapshot {
    pub fn new(
        source_revision: FileRevision,
        content_hash: FileContentHash,
        content_kind: FileContentKind,
        original_bytes: u64,
        stored_bytes: u64,
        compression: SnapshotCompression,
    ) -> Result<Self, InvalidBackup> {
        if original_bytes != source_revision.size() {
            return Err(InvalidBackup::SnapshotSizeMismatch);
        }
        if original_bytes > 0 && stored_bytes == 0 {
            return Err(InvalidBackup::EmptyStoredSnapshot);
        }

        Ok(Self {
            source_revision,
            content_hash,
            content_kind,
            original_bytes,
            stored_bytes,
            compression,
        })
    }

    pub const fn source_revision(&self) -> &FileRevision {
        &self.source_revision
    }

    pub const fn content_hash(&self) -> &FileContentHash {
        &self.content_hash
    }

    pub const fn content_kind(&self) -> FileContentKind {
        self.content_kind
    }

    pub const fn original_bytes(&self) -> u64 {
        self.original_bytes
    }

    pub const fn stored_bytes(&self) -> u64 {
        self.stored_bytes
    }

    pub const fn compression(&self) -> SnapshotCompression {
        self.compression
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupDiffSkipReason {
    BinaryContent,
    Disabled,
    InputTooLarge,
    UnsupportedEncoding,
    GenerationTimedOut,
    GenerationFailed,
}

/// Pre-calculated Diff Match Patch text or an explicit reason why generating
/// one was not useful or possible. A skipped diff never prevents preserving
/// the complete snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupDiff {
    DiffMatchPatch(String),
    Skipped(BackupDiffSkipReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupState {
    Preparing { lease_expires_at: DateTime<Utc> },
    Available,
    Restoring { lease_expires_at: DateTime<Utc> },
    Deleting { lease_expires_at: DateTime<Utc> },
    PreparationFailed,
}

impl BackupState {
    pub fn lease_expires_at(self) -> Option<DateTime<Utc>> {
        match self {
            Self::Preparing { lease_expires_at }
            | Self::Restoring { lease_expires_at }
            | Self::Deleting { lease_expires_at } => Some(lease_expires_at),
            Self::Available | Self::PreparationFailed => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    id: BackupId,
    mutation_id: MutationId,
    source: BackupSource,
    action: BackupAction,
    initiated_by: BackupInitiatorId,
    source_revision: FileRevision,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    state: BackupState,
    snapshot: Option<BackupSnapshot>,
    diff: Option<BackupDiff>,
    version: BackupVersion,
}

impl Backup {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        id: BackupId,
        mutation_id: MutationId,
        source: BackupSource,
        action: BackupAction,
        initiated_by: BackupInitiatorId,
        source_revision: FileRevision,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<Self, InvalidBackup> {
        if expires_at <= created_at {
            return Err(InvalidBackup::Expiration);
        }
        if lease_expires_at <= created_at || lease_expires_at > expires_at {
            return Err(InvalidBackup::Lease);
        }

        Ok(Self {
            id,
            mutation_id,
            source,
            action,
            initiated_by,
            source_revision,
            created_at,
            expires_at,
            state: BackupState::Preparing { lease_expires_at },
            snapshot: None,
            diff: None,
            version: BackupVersion::initial(),
        })
    }

    /// Reconstitutes a persisted aggregate while enforcing the same
    /// invariants as live state transitions. Infrastructure adapters must use
    /// this constructor instead of bypassing private fields.
    #[allow(clippy::too_many_arguments)]
    pub fn rehydrate(
        id: BackupId,
        mutation_id: MutationId,
        source: BackupSource,
        action: BackupAction,
        initiated_by: BackupInitiatorId,
        source_revision: FileRevision,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        state: BackupState,
        snapshot: Option<BackupSnapshot>,
        diff: Option<BackupDiff>,
        version: BackupVersion,
    ) -> Result<Self, InvalidBackup> {
        if expires_at <= created_at {
            return Err(InvalidBackup::Expiration);
        }
        if state
            .lease_expires_at()
            .is_some_and(|lease| lease <= created_at)
        {
            return Err(InvalidBackup::Lease);
        }
        if matches!(state, BackupState::Preparing { .. })
            && state
                .lease_expires_at()
                .is_some_and(|lease| lease > expires_at)
        {
            return Err(InvalidBackup::Lease);
        }

        let has_material = snapshot.is_some() && diff.is_some();
        let has_no_material = snapshot.is_none() && diff.is_none();
        let valid_shape = match state {
            BackupState::Preparing { .. } | BackupState::PreparationFailed => has_no_material,
            BackupState::Available | BackupState::Restoring { .. } => has_material,
            BackupState::Deleting { .. } => has_material || has_no_material,
        };
        if !valid_shape {
            return Err(InvalidBackup::PersistedState);
        }

        if let (Some(snapshot), Some(diff)) = (&snapshot, &diff) {
            validate_snapshot_material(&source_revision, snapshot, diff)?;
        }

        Ok(Self {
            id,
            mutation_id,
            source,
            action,
            initiated_by,
            source_revision,
            created_at,
            expires_at,
            state,
            snapshot,
            diff,
            version,
        })
    }

    pub fn mark_available(
        &mut self,
        snapshot: BackupSnapshot,
        diff: BackupDiff,
    ) -> Result<(), InvalidBackup> {
        if !matches!(self.state, BackupState::Preparing { .. }) {
            return Err(InvalidBackup::StateTransition);
        }
        validate_snapshot_material(&self.source_revision, &snapshot, &diff)?;

        let version = self.version.next()?;
        self.snapshot = Some(snapshot);
        self.diff = Some(diff);
        self.state = BackupState::Available;
        self.version = version;
        Ok(())
    }

    pub fn fail_preparation(&mut self) -> Result<(), InvalidBackup> {
        if !matches!(self.state, BackupState::Preparing { .. }) {
            return Err(InvalidBackup::StateTransition);
        }
        self.version = self.version.next()?;
        self.state = BackupState::PreparationFailed;
        Ok(())
    }

    pub fn begin_restore(
        &mut self,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<(), InvalidBackup> {
        self.ensure_available_operation(now, lease_expires_at)?;
        self.version = self.version.next()?;
        self.state = BackupState::Restoring { lease_expires_at };
        Ok(())
    }

    pub fn begin_deletion(
        &mut self,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<(), InvalidBackup> {
        if !matches!(
            self.state,
            BackupState::Available | BackupState::PreparationFailed
        ) {
            return Err(InvalidBackup::StateTransition);
        }
        validate_operation_lease(now, lease_expires_at)?;
        self.version = self.version.next()?;
        self.state = BackupState::Deleting { lease_expires_at };
        Ok(())
    }

    pub fn release_operation(&mut self) -> Result<(), InvalidBackup> {
        if !matches!(
            self.state,
            BackupState::Restoring { .. } | BackupState::Deleting { .. }
        ) {
            return Err(InvalidBackup::StateTransition);
        }
        self.version = self.version.next()?;
        self.state = if self.snapshot.is_some() {
            BackupState::Available
        } else {
            BackupState::PreparationFailed
        };
        Ok(())
    }

    fn ensure_available_operation(
        &self,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<(), InvalidBackup> {
        if self.state != BackupState::Available || self.snapshot.is_none() {
            return Err(InvalidBackup::StateTransition);
        }
        if self.expires_at <= now {
            return Err(InvalidBackup::Expired);
        }
        validate_operation_lease(now, lease_expires_at)
    }

    pub const fn id(&self) -> BackupId {
        self.id
    }

    pub const fn mutation_id(&self) -> MutationId {
        self.mutation_id
    }

    pub const fn source(&self) -> &BackupSource {
        &self.source
    }

    pub const fn action(&self) -> BackupAction {
        self.action
    }

    pub const fn initiated_by(&self) -> BackupInitiatorId {
        self.initiated_by
    }

    pub const fn source_revision(&self) -> &FileRevision {
        &self.source_revision
    }

    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn state(&self) -> BackupState {
        self.state
    }

    pub const fn snapshot(&self) -> Option<&BackupSnapshot> {
        self.snapshot.as_ref()
    }

    pub const fn diff(&self) -> Option<&BackupDiff> {
        self.diff.as_ref()
    }

    pub const fn version(&self) -> BackupVersion {
        self.version
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    pub fn has_expired_lease(&self, now: DateTime<Utc>) -> bool {
        self.state
            .lease_expires_at()
            .is_some_and(|expires_at| expires_at <= now)
    }
}

fn validate_snapshot_material(
    source_revision: &FileRevision,
    snapshot: &BackupSnapshot,
    diff: &BackupDiff,
) -> Result<(), InvalidBackup> {
    if snapshot.source_revision() != source_revision {
        return Err(InvalidBackup::SnapshotRevisionMismatch);
    }
    if snapshot.content_kind() == FileContentKind::Binary
        && matches!(diff, BackupDiff::DiffMatchPatch(_))
    {
        return Err(InvalidBackup::BinaryDiff);
    }
    Ok(())
}

fn validate_operation_lease(
    now: DateTime<Utc>,
    lease_expires_at: DateTime<Utc>,
) -> Result<(), InvalidBackup> {
    if lease_expires_at <= now {
        Err(InvalidBackup::Lease)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidBackup {
    #[error("backup initiator ID must be a positive integer")]
    InitiatorId,
    #[error("backup source cannot be a storage capability root")]
    SourceRoot,
    #[error("file mutation does not require a content backup")]
    UnsupportedMutation,
    #[error("backup expiration must be later than its creation time")]
    Expiration,
    #[error("backup operation lease has invalid bounds")]
    Lease,
    #[error("backup snapshot size differs from the observed source revision")]
    SnapshotSizeMismatch,
    #[error("a non-empty source cannot have an empty stored snapshot")]
    EmptyStoredSnapshot,
    #[error("backup snapshot belongs to another source revision")]
    SnapshotRevisionMismatch,
    #[error("a Diff Match Patch cannot be attached to binary content")]
    BinaryDiff,
    #[error("backup state transition is not allowed")]
    StateTransition,
    #[error("persisted backup state is inconsistent with its snapshot or diff")]
    PersistedState,
    #[error("expired backup cannot be restored")]
    Expired,
    #[error("backup aggregate version overflowed")]
    VersionOverflow,
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};

    use super::*;
    use crate::shared::file_storage::mutation::{ContentHashAlgorithm, FileContentHash};

    fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000, 0).unwrap()
    }

    fn revision() -> FileRevision {
        FileRevision::from_metadata(8, now())
    }

    fn source() -> BackupSource {
        BackupSource::new(
            StorageNamespace::new("configuration").unwrap(),
            RelativeStoragePath::new("gamemodes/main.amx").unwrap(),
        )
        .unwrap()
    }

    fn prepared() -> Backup {
        Backup::prepare(
            BackupId::new(),
            MutationId::new(),
            source(),
            BackupAction::Overwrite,
            BackupInitiatorId::new(42).unwrap(),
            revision(),
            now(),
            now() + Duration::days(14),
            now() + Duration::minutes(5),
        )
        .unwrap()
    }

    fn snapshot(kind: FileContentKind) -> BackupSnapshot {
        BackupSnapshot::new(
            revision(),
            FileContentHash::new(ContentHashAlgorithm::Sha256, "12".repeat(32)).unwrap(),
            kind,
            8,
            6,
            SnapshotCompression::Gzip,
        )
        .unwrap()
    }

    #[test]
    fn identifiers_are_typed_and_round_trip() {
        let id = BackupId::new();
        assert_eq!(id.to_string().parse::<BackupId>().unwrap(), id);
        assert_eq!(BackupId::from_uuid(id.as_uuid()), id);
        assert_eq!(BackupInitiatorId::new(42).unwrap().get(), 42);
        assert!(BackupInitiatorId::new(0).is_err());
    }

    #[test]
    fn only_overwrite_and_delete_require_snapshots() {
        assert_eq!(
            BackupAction::try_from(FileMutationKind::Overwrite).unwrap(),
            BackupAction::Overwrite
        );
        assert_eq!(
            BackupAction::try_from(FileMutationKind::Delete).unwrap(),
            BackupAction::Delete
        );
        assert_eq!(
            BackupAction::try_from(FileMutationKind::Create),
            Err(InvalidBackup::UnsupportedMutation)
        );
        assert_eq!(
            BackupAction::try_from(FileMutationKind::Rename),
            Err(InvalidBackup::UnsupportedMutation)
        );
    }

    #[test]
    fn prepares_and_completes_a_backup_with_snapshot_and_diff() {
        let mut backup = prepared();
        let snapshot = snapshot(FileContentKind::Text);

        backup
            .mark_available(
                snapshot.clone(),
                BackupDiff::DiffMatchPatch("@@ -1 +1 @@".into()),
            )
            .unwrap();

        assert_eq!(backup.state(), BackupState::Available);
        assert_eq!(backup.version().get(), 1);
        assert_eq!(backup.snapshot(), Some(&snapshot));
        assert!(matches!(backup.diff(), Some(BackupDiff::DiffMatchPatch(_))));
        assert_eq!(backup.initiated_by().get(), 42);
    }

    #[test]
    fn binary_snapshot_requires_an_explicitly_skipped_diff() {
        let mut backup = prepared();

        assert_eq!(
            backup.mark_available(
                snapshot(FileContentKind::Binary),
                BackupDiff::DiffMatchPatch("binary".into()),
            ),
            Err(InvalidBackup::BinaryDiff)
        );
        backup
            .mark_available(
                snapshot(FileContentKind::Binary),
                BackupDiff::Skipped(BackupDiffSkipReason::BinaryContent),
            )
            .unwrap();
        assert_eq!(backup.state(), BackupState::Available);
    }

    #[test]
    fn validates_snapshot_revision_and_sizes() {
        assert_eq!(
            BackupSnapshot::new(
                revision(),
                FileContentHash::new(ContentHashAlgorithm::Sha256, "12".repeat(32)).unwrap(),
                FileContentKind::Text,
                7,
                7,
                SnapshotCompression::None,
            ),
            Err(InvalidBackup::SnapshotSizeMismatch)
        );

        let mut backup = prepared();
        let other_revision = FileRevision::from_metadata(8, now() + Duration::seconds(1));
        let other = BackupSnapshot::new(
            other_revision,
            FileContentHash::new(ContentHashAlgorithm::Sha256, "12".repeat(32)).unwrap(),
            FileContentKind::Text,
            8,
            8,
            SnapshotCompression::None,
        )
        .unwrap();
        assert_eq!(
            backup.mark_available(other, BackupDiff::DiffMatchPatch(String::new())),
            Err(InvalidBackup::SnapshotRevisionMismatch)
        );
    }

    #[test]
    fn leases_serialize_restore_and_delete_operations() {
        let mut backup = prepared();
        backup
            .mark_available(
                snapshot(FileContentKind::Text),
                BackupDiff::DiffMatchPatch(String::new()),
            )
            .unwrap();
        let lease = now() + Duration::minutes(5);

        backup.begin_restore(now(), lease).unwrap();
        assert_eq!(backup.version().get(), 2);
        assert_eq!(
            backup.begin_deletion(now(), lease),
            Err(InvalidBackup::StateTransition)
        );
        assert!(backup.has_expired_lease(lease));
        backup.release_operation().unwrap();
        backup.begin_deletion(now(), lease).unwrap();
        backup.release_operation().unwrap();
        assert_eq!(backup.state(), BackupState::Available);
        assert_eq!(backup.version().get(), 5);
    }

    #[test]
    fn rejects_invalid_dates_and_expired_restore() {
        let base = prepared();
        assert_eq!(
            Backup::prepare(
                BackupId::new(),
                MutationId::new(),
                source(),
                BackupAction::Delete,
                BackupInitiatorId::new(42).unwrap(),
                revision(),
                now(),
                now(),
                now() + Duration::minutes(1),
            ),
            Err(InvalidBackup::Expiration)
        );

        let mut backup = base;
        backup
            .mark_available(
                snapshot(FileContentKind::Text),
                BackupDiff::DiffMatchPatch(String::new()),
            )
            .unwrap();
        assert_eq!(
            backup.begin_restore(
                now() + Duration::days(14),
                now() + Duration::days(14) + Duration::minutes(5),
            ),
            Err(InvalidBackup::Expired)
        );
    }

    #[test]
    fn rehydration_rejects_inconsistent_persisted_state() {
        let backup = prepared();

        assert_eq!(
            Backup::rehydrate(
                backup.id(),
                backup.mutation_id(),
                backup.source().clone(),
                backup.action(),
                backup.initiated_by(),
                backup.source_revision().clone(),
                backup.created_at(),
                backup.expires_at(),
                BackupState::Available,
                None,
                None,
                BackupVersion::from_value(4),
            ),
            Err(InvalidBackup::PersistedState)
        );
    }
}
