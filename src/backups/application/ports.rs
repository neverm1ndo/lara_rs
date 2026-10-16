use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use thiserror::Error;
use tokio::io::AsyncRead;

use crate::{
    backups::domain::{
        Backup, BackupDiff, BackupDiffSkipReason, BackupId, BackupSource, BackupVersion,
        SnapshotCompression,
    },
    shared::file_storage::{
        content::FileContentKind, mutation::FileContentHash, path::RelativeStoragePath,
    },
};

pub type BackupRepositoryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, BackupRepositoryError>> + Send + 'a>>;

/// Metadata persistence port. `save` and `delete` must compare the persisted
/// version with `expected_version` atomically. MongoDB implementations should
/// express this as one conditional update/delete, not a read-then-write pair.
pub trait BackupRepository: Send + Sync {
    fn insert<'a>(&'a self, backup: &'a Backup) -> BackupRepositoryFuture<'a, ()>;

    fn find_by_id<'a>(&'a self, backup_id: BackupId) -> BackupRepositoryFuture<'a, Option<Backup>>;

    fn list<'a>(&'a self, query: BackupListQuery) -> BackupRepositoryFuture<'a, Vec<Backup>>;

    fn find_expired<'a>(
        &'a self,
        expired_at_or_before: DateTime<Utc>,
        limit: usize,
    ) -> BackupRepositoryFuture<'a, Vec<Backup>>;

    fn find_stale_preparations<'a>(
        &'a self,
        lease_expired_at_or_before: DateTime<Utc>,
        limit: usize,
    ) -> BackupRepositoryFuture<'a, Vec<Backup>>;

    fn save<'a>(
        &'a self,
        backup: &'a Backup,
        expected_version: BackupVersion,
    ) -> BackupRepositoryFuture<'a, ()>;

    fn delete<'a>(
        &'a self,
        backup_id: BackupId,
        expected_version: BackupVersion,
    ) -> BackupRepositoryFuture<'a, ()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupListCursor {
    pub created_at: DateTime<Utc>,
    pub backup_id: BackupId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupListQuery {
    pub cursor: Option<BackupListCursor>,
    pub limit: usize,
}

impl BackupListQuery {
    pub fn new(
        cursor: Option<BackupListCursor>,
        limit: usize,
    ) -> Result<Self, InvalidBackupPortInput> {
        if limit == 0 {
            return Err(InvalidBackupPortInput::EmptyPage);
        }
        Ok(Self { cursor, limit })
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum BackupRepositoryError {
    #[error("backup metadata already exists")]
    AlreadyExists,
    #[error("backup metadata was concurrently modified")]
    ConcurrentModification,
    #[error("backup metadata is invalid: {message}")]
    InvalidData { message: String },
    #[error("backup metadata repository is unavailable: {message}")]
    Unavailable { message: String },
}

pub type BackupSnapshotStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, BackupSnapshotStoreError>> + Send + 'a>>;
pub type BackupSnapshotReader = Pin<Box<dyn AsyncRead + Send>>;

/// Opaque snapshot payload preserved byte-for-byte. Compression belongs to
/// the storage adapter and never changes the bytes returned by `open`.
pub struct BackupSnapshotWrite<'a> {
    pub backup_id: BackupId,
    pub content: &'a [u8],
    pub compression: SnapshotCompression,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBackupSnapshot {
    pub stored_bytes: u64,
    pub content_hash: FileContentHash,
    pub compression: SnapshotCompression,
}

pub struct OpenedBackupSnapshot {
    pub reader: BackupSnapshotReader,
    pub original_bytes: u64,
    pub content_hash: FileContentHash,
}

/// Snapshot store implementations must publish writes atomically (temporary
/// file plus rename) and make repeated removal idempotent. A metadata record
/// must never point at a partially written file.
pub trait BackupSnapshotStore: Send + Sync {
    fn persist<'a>(
        &'a self,
        write: BackupSnapshotWrite<'a>,
    ) -> BackupSnapshotStoreFuture<'a, StoredBackupSnapshot>;

    fn open<'a>(
        &'a self,
        backup_id: BackupId,
        expected_hash: &'a FileContentHash,
        compression: SnapshotCompression,
    ) -> BackupSnapshotStoreFuture<'a, OpenedBackupSnapshot>;

    fn remove<'a>(&'a self, backup_id: BackupId) -> BackupSnapshotStoreFuture<'a, ()>;
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum BackupSnapshotStoreError {
    #[error("backup snapshot already exists")]
    AlreadyExists,
    #[error("backup snapshot does not exist")]
    NotFound,
    #[error("backup snapshot content hash does not match its metadata")]
    IntegrityMismatch,
    #[error("backup snapshot store is unavailable: {message}")]
    Unavailable { message: String },
}

pub type BackupDiffFuture<'a> =
    Pin<Box<dyn Future<Output = Result<BackupDiff, BackupDiffError>> + Send + 'a>>;

pub struct BackupDiffInput<'a> {
    pub source: &'a BackupSource,
    pub content_kind: FileContentKind,
    pub before: &'a [u8],
    /// Exact replacement bytes for overwrite; `None` means deletion and is
    /// interpreted as an empty target document.
    pub after: Option<&'a [u8]>,
}

/// Port for bounded, pre-calculated Diff Match Patch generation. Binary input
/// must return `Skipped(BinaryContent)` without invoking a text decoder.
pub trait BackupDiffGenerator: Send + Sync {
    fn generate<'a>(&'a self, input: BackupDiffInput<'a>) -> BackupDiffFuture<'a>;
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum BackupDiffError {
    #[error("backup diff generation failed: {message}")]
    Failed { message: String },
}

pub trait BackupClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

pub trait BackupIdGenerator: Send + Sync {
    fn next_id(&self) -> BackupId;
}

/// Destination port used by restore. The implementation resolves a namespace
/// to its capability-scoped storage; absolute paths never cross this boundary.
pub trait BackupRestoreTarget: Send + Sync {
    fn restore<'a>(
        &'a self,
        source: &'a BackupSource,
        content: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), BackupRestoreError>> + Send + 'a>>;
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum BackupRestoreError {
    #[error("backup source namespace has no restore target")]
    UnknownNamespace,
    #[error("backup restore target rejected path {path}")]
    InvalidPath { path: RelativeStoragePath },
    #[error("backup restore target was concurrently modified")]
    ConcurrentModification,
    #[error("backup restore target is unavailable: {message}")]
    Unavailable { message: String },
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidBackupPortInput {
    #[error("backup page size must be greater than zero")]
    EmptyPage,
}

/// Helper shared by diff adapters that need an explicit result for binary
/// input while keeping snapshot creation successful.
pub const fn skipped_binary_diff() -> BackupDiff {
    BackupDiff::Skipped(BackupDiffSkipReason::BinaryContent)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn validates_page_size_and_preserves_stable_cursor() {
        assert_eq!(
            BackupListQuery::new(None, 0),
            Err(InvalidBackupPortInput::EmptyPage)
        );

        let cursor = BackupListCursor {
            created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            backup_id: BackupId::new(),
        };
        let query = BackupListQuery::new(Some(cursor), 50).unwrap();

        assert_eq!(query.cursor, Some(cursor));
        assert_eq!(query.limit, 50);
    }

    #[test]
    fn binary_diff_helper_is_explicitly_non_textual() {
        assert_eq!(
            skipped_binary_diff(),
            BackupDiff::Skipped(BackupDiffSkipReason::BinaryContent)
        );
    }
}
