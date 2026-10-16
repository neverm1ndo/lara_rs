use std::{io, sync::Arc, time::Duration as StdDuration};

use chrono::Duration;
use thiserror::Error;
use tokio::io::AsyncReadExt;

use crate::backups::{
    application::ports::{
        BackupClock, BackupListQuery, BackupRepository, BackupRepositoryError, BackupRestoreError,
        BackupRestoreTarget, BackupSnapshotReader, BackupSnapshotStore, BackupSnapshotStoreError,
    },
    domain::{Backup, BackupId, BackupState, BackupVersion, InvalidBackup},
};

pub struct OpenedBackupContent {
    pub backup: Backup,
    pub reader: BackupSnapshotReader,
    pub content_length: u64,
}

/// Coordinates metadata and immutable snapshot operations. State transitions
/// are persisted with compare-and-swap before filesystem effects begin.
pub struct BackupLifecycleService {
    repository: Arc<dyn BackupRepository>,
    snapshots: Arc<dyn BackupSnapshotStore>,
    restore_target: Arc<dyn BackupRestoreTarget>,
    clock: Arc<dyn BackupClock>,
    operation_lease: Duration,
}

impl BackupLifecycleService {
    pub fn new(
        repository: Arc<dyn BackupRepository>,
        snapshots: Arc<dyn BackupSnapshotStore>,
        restore_target: Arc<dyn BackupRestoreTarget>,
        clock: Arc<dyn BackupClock>,
        operation_lease: StdDuration,
    ) -> Result<Self, InvalidBackupLifecyclePolicy> {
        if operation_lease.is_zero() {
            return Err(InvalidBackupLifecyclePolicy::OperationLease);
        }
        let operation_lease = Duration::from_std(operation_lease)
            .map_err(|_| InvalidBackupLifecyclePolicy::OperationLease)?;

        Ok(Self {
            repository,
            snapshots,
            restore_target,
            clock,
            operation_lease,
        })
    }

    pub async fn list(&self, query: BackupListQuery) -> Result<Vec<Backup>, BackupLifecycleError> {
        self.repository.list(query).await.map_err(Into::into)
    }

    pub async fn open(
        &self,
        backup_id: BackupId,
    ) -> Result<OpenedBackupContent, BackupLifecycleError> {
        let backup = self.available_backup(backup_id, false).await?;
        let snapshot = backup
            .snapshot()
            .ok_or(BackupLifecycleError::UnavailableState)?;
        let opened = self
            .snapshots
            .open(backup.id(), snapshot.content_hash(), snapshot.compression())
            .await?;
        if opened.original_bytes != snapshot.original_bytes() {
            return Err(BackupLifecycleError::SnapshotLengthMismatch);
        }

        Ok(OpenedBackupContent {
            backup,
            reader: opened.reader,
            content_length: opened.original_bytes,
        })
    }

    pub async fn restore(&self, backup_id: BackupId) -> Result<(), BackupLifecycleError> {
        let mut backup = self.available_backup(backup_id, true).await?;
        let now = self.clock.now();
        let lease_expires_at = now
            .checked_add_signed(self.operation_lease)
            .ok_or(BackupLifecycleError::TimeOverflow)?;
        let expected_version = backup.version();
        backup.begin_restore(now, lease_expires_at)?;
        self.repository.save(&backup, expected_version).await?;
        let operation_version = backup.version();

        let result = self.restore_reserved(&backup).await;
        if let Err(error) = result {
            self.release_operation(&mut backup, operation_version).await;
            return Err(error);
        }

        backup.release_operation()?;
        self.repository.save(&backup, operation_version).await?;
        Ok(())
    }

    pub async fn remove(&self, backup_id: BackupId) -> Result<(), BackupLifecycleError> {
        let mut backup = self
            .repository
            .find_by_id(backup_id)
            .await?
            .ok_or(BackupLifecycleError::NotFound)?;
        let now = self.clock.now();
        let lease_expires_at = now
            .checked_add_signed(self.operation_lease)
            .ok_or(BackupLifecycleError::TimeOverflow)?;
        let expected_version = backup.version();
        backup.begin_deletion(now, lease_expires_at)?;
        self.repository.save(&backup, expected_version).await?;
        let deletion_version = backup.version();

        if let Err(error) = self.snapshots.remove(backup.id()).await {
            self.release_operation(&mut backup, deletion_version).await;
            return Err(error.into());
        }
        self.repository
            .delete(backup.id(), deletion_version)
            .await?;
        Ok(())
    }

    async fn available_backup(
        &self,
        backup_id: BackupId,
        reject_expired: bool,
    ) -> Result<Backup, BackupLifecycleError> {
        let backup = self
            .repository
            .find_by_id(backup_id)
            .await?
            .ok_or(BackupLifecycleError::NotFound)?;
        if backup.state() != BackupState::Available {
            return Err(BackupLifecycleError::UnavailableState);
        }
        if reject_expired && backup.is_expired(self.clock.now()) {
            return Err(BackupLifecycleError::Expired);
        }
        Ok(backup)
    }

    async fn restore_reserved(&self, backup: &Backup) -> Result<(), BackupLifecycleError> {
        let snapshot = backup
            .snapshot()
            .ok_or(BackupLifecycleError::UnavailableState)?;
        let opened = self
            .snapshots
            .open(backup.id(), snapshot.content_hash(), snapshot.compression())
            .await?;
        if opened.original_bytes != snapshot.original_bytes() {
            return Err(BackupLifecycleError::SnapshotLengthMismatch);
        }
        let capacity = usize::try_from(opened.original_bytes)
            .map_err(|_| BackupLifecycleError::SnapshotTooLarge)?;
        let read_limit = opened
            .original_bytes
            .checked_add(1)
            .ok_or(BackupLifecycleError::SnapshotTooLarge)?;
        let mut content = Vec::with_capacity(capacity);
        opened
            .reader
            .take(read_limit)
            .read_to_end(&mut content)
            .await
            .map_err(BackupLifecycleError::SnapshotRead)?;
        if content.len() as u64 != opened.original_bytes {
            return Err(BackupLifecycleError::SnapshotLengthMismatch);
        }

        self.restore_target
            .restore(backup.source(), &content)
            .await?;
        Ok(())
    }

    async fn release_operation(&self, backup: &mut Backup, expected_version: BackupVersion) {
        if backup.release_operation().is_ok()
            && let Err(error) = self.repository.save(backup, expected_version).await
        {
            tracing::warn!(
                error = %error,
                backup_id = %backup.id(),
                "failed to release backup operation lease"
            );
        }
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidBackupLifecyclePolicy {
    #[error("backup operation lease must be greater than zero and fit chrono duration")]
    OperationLease,
}

#[derive(Debug, Error)]
pub enum BackupLifecycleError {
    #[error("backup does not exist")]
    NotFound,
    #[error("backup is not available for this operation")]
    UnavailableState,
    #[error("expired backup cannot be restored")]
    Expired,
    #[error("backup operation timestamp overflow")]
    TimeOverflow,
    #[error("backup snapshot length differs from metadata")]
    SnapshotLengthMismatch,
    #[error("backup snapshot is too large for this platform")]
    SnapshotTooLarge,
    #[error("failed to read backup snapshot: {0}")]
    SnapshotRead(io::Error),
    #[error(transparent)]
    Domain(#[from] InvalidBackup),
    #[error(transparent)]
    Repository(#[from] BackupRepositoryError),
    #[error(transparent)]
    Snapshot(#[from] BackupSnapshotStoreError),
    #[error(transparent)]
    Restore(#[from] BackupRestoreError),
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use chrono::{DateTime, TimeZone, Utc};

    use super::*;
    use crate::{
        backups::{
            application::ports::{
                BackupListCursor, BackupRepositoryFuture, BackupSnapshotStoreFuture,
                OpenedBackupSnapshot,
            },
            domain::{
                BackupAction, BackupDiff, BackupId, BackupInitiatorId, BackupSnapshot,
                BackupSource, SnapshotCompression,
            },
        },
        shared::file_storage::{
            content::FileContentKind,
            mutation::{
                ContentHashAlgorithm, FileContentHash, FileRevision, MutationId, StorageNamespace,
            },
            path::RelativeStoragePath,
        },
    };

    struct SingleRepository {
        backup: Mutex<Option<Backup>>,
        order: Arc<Mutex<Vec<&'static str>>>,
    }

    impl BackupRepository for SingleRepository {
        fn insert<'a>(&'a self, _backup: &'a Backup) -> BackupRepositoryFuture<'a, ()> {
            Box::pin(async { unreachable!() })
        }

        fn find_by_id<'a>(
            &'a self,
            backup_id: BackupId,
        ) -> BackupRepositoryFuture<'a, Option<Backup>> {
            Box::pin(async move {
                Ok(self
                    .backup
                    .lock()
                    .unwrap()
                    .as_ref()
                    .filter(|backup| backup.id() == backup_id)
                    .cloned())
            })
        }

        fn find_by_mutation_id<'a>(
            &'a self,
            mutation_id: MutationId,
        ) -> BackupRepositoryFuture<'a, Option<Backup>> {
            Box::pin(async move {
                Ok(self
                    .backup
                    .lock()
                    .unwrap()
                    .as_ref()
                    .filter(|backup| backup.mutation_id() == mutation_id)
                    .cloned())
            })
        }

        fn list<'a>(&'a self, _query: BackupListQuery) -> BackupRepositoryFuture<'a, Vec<Backup>> {
            Box::pin(async move { Ok(self.backup.lock().unwrap().clone().into_iter().collect()) })
        }

        fn find_expired<'a>(
            &'a self,
            _at: DateTime<Utc>,
            _limit: usize,
        ) -> BackupRepositoryFuture<'a, Vec<Backup>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn find_stale_preparations<'a>(
            &'a self,
            _at: DateTime<Utc>,
            _limit: usize,
        ) -> BackupRepositoryFuture<'a, Vec<Backup>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn find_stale_operations<'a>(
            &'a self,
            _at: DateTime<Utc>,
            _limit: usize,
        ) -> BackupRepositoryFuture<'a, Vec<Backup>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn save<'a>(
            &'a self,
            backup: &'a Backup,
            expected_version: BackupVersion,
        ) -> BackupRepositoryFuture<'a, ()> {
            Box::pin(async move {
                let mut current = self.backup.lock().unwrap();
                if current
                    .as_ref()
                    .is_none_or(|value| value.version() != expected_version)
                {
                    return Err(BackupRepositoryError::ConcurrentModification);
                }
                *current = Some(backup.clone());
                Ok(())
            })
        }

        fn delete<'a>(
            &'a self,
            backup_id: BackupId,
            expected_version: BackupVersion,
        ) -> BackupRepositoryFuture<'a, ()> {
            Box::pin(async move {
                let mut current = self.backup.lock().unwrap();
                if current.as_ref().is_none_or(|value| {
                    value.id() != backup_id || value.version() != expected_version
                }) {
                    return Err(BackupRepositoryError::ConcurrentModification);
                }
                self.order.lock().unwrap().push("metadata");
                *current = None;
                Ok(())
            })
        }
    }

    struct MemorySnapshots {
        content: Vec<u8>,
        reported_length: u64,
        fail_remove: bool,
        order: Arc<Mutex<Vec<&'static str>>>,
    }

    impl BackupSnapshotStore for MemorySnapshots {
        fn persist<'a>(
            &'a self,
            _write: crate::backups::application::ports::BackupSnapshotWrite<'a>,
        ) -> BackupSnapshotStoreFuture<'a, crate::backups::application::ports::StoredBackupSnapshot>
        {
            Box::pin(async { unreachable!() })
        }

        fn open<'a>(
            &'a self,
            _backup_id: BackupId,
            expected_hash: &'a FileContentHash,
            _compression: SnapshotCompression,
        ) -> BackupSnapshotStoreFuture<'a, OpenedBackupSnapshot> {
            Box::pin(async move {
                Ok(OpenedBackupSnapshot {
                    reader: Box::pin(std::io::Cursor::new(self.content.clone())),
                    original_bytes: self.reported_length,
                    content_hash: expected_hash.clone(),
                })
            })
        }

        fn remove<'a>(&'a self, _backup_id: BackupId) -> BackupSnapshotStoreFuture<'a, ()> {
            Box::pin(async move {
                if self.fail_remove {
                    return Err(BackupSnapshotStoreError::Unavailable {
                        message: "disk".into(),
                    });
                }
                self.order.lock().unwrap().push("snapshot");
                Ok(())
            })
        }
    }

    struct RecordingRestore {
        content: Mutex<Vec<u8>>,
        fail: bool,
    }

    type TestService = (
        BackupLifecycleService,
        Arc<SingleRepository>,
        Arc<RecordingRestore>,
        Arc<Mutex<Vec<&'static str>>>,
    );

    impl BackupRestoreTarget for RecordingRestore {
        fn restore<'a>(
            &'a self,
            _source: &'a BackupSource,
            content: &'a [u8],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), BackupRestoreError>> + Send + 'a>,
        > {
            Box::pin(async move {
                if self.fail {
                    return Err(BackupRestoreError::Unavailable {
                        message: "target".into(),
                    });
                }
                *self.content.lock().unwrap() = content.to_vec();
                Ok(())
            })
        }
    }

    #[derive(Clone, Copy)]
    struct FixedClock(DateTime<Utc>);

    impl BackupClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000, 0).unwrap()
    }

    fn available_backup() -> Backup {
        let revision = FileRevision::from_metadata(3, now());
        let hash = FileContentHash::new(ContentHashAlgorithm::Sha256, "00".repeat(32)).unwrap();
        let mut backup = Backup::prepare(
            BackupId::new(),
            MutationId::new(),
            BackupSource::new(
                StorageNamespace::new("configuration").unwrap(),
                RelativeStoragePath::new("server.cfg").unwrap(),
            )
            .unwrap(),
            BackupAction::Overwrite,
            BackupInitiatorId::new(42).unwrap(),
            revision.clone(),
            now(),
            now() + Duration::hours(1),
            now() + Duration::minutes(1),
        )
        .unwrap();
        backup
            .mark_available(
                BackupSnapshot::new(
                    revision,
                    hash,
                    FileContentKind::Text,
                    3,
                    3,
                    SnapshotCompression::None,
                )
                .unwrap(),
                BackupDiff::DiffMatchPatch("@@ patch @@".into()),
            )
            .unwrap();
        backup
    }

    fn service(
        backup: Backup,
        snapshot_content: Vec<u8>,
        reported_length: u64,
        restore_fails: bool,
        remove_fails: bool,
    ) -> TestService {
        let order = Arc::new(Mutex::new(Vec::new()));
        let repository = Arc::new(SingleRepository {
            backup: Mutex::new(Some(backup)),
            order: order.clone(),
        });
        let snapshots = Arc::new(MemorySnapshots {
            content: snapshot_content,
            reported_length,
            fail_remove: remove_fails,
            order: order.clone(),
        });
        let target = Arc::new(RecordingRestore {
            content: Mutex::new(Vec::new()),
            fail: restore_fails,
        });
        let service = BackupLifecycleService::new(
            repository.clone(),
            snapshots,
            target.clone(),
            Arc::new(FixedClock(now() + Duration::minutes(2))),
            StdDuration::from_secs(60),
        )
        .unwrap();
        (service, repository, target, order)
    }

    #[tokio::test]
    async fn restore_holds_a_lease_and_returns_backup_to_available_state() {
        let backup = available_backup();
        let id = backup.id();
        let (service, repository, target, _) = service(backup, b"old".to_vec(), 3, false, false);

        service.restore(id).await.unwrap();

        assert_eq!(&*target.content.lock().unwrap(), b"old");
        assert_eq!(
            repository.backup.lock().unwrap().as_ref().unwrap().state(),
            BackupState::Available
        );
    }

    #[tokio::test]
    async fn failed_restore_releases_the_operation_lease() {
        let backup = available_backup();
        let id = backup.id();
        let (service, repository, _, _) = service(backup, b"old".to_vec(), 3, true, false);

        assert!(service.restore(id).await.is_err());

        assert_eq!(
            repository.backup.lock().unwrap().as_ref().unwrap().state(),
            BackupState::Available
        );
    }

    #[tokio::test]
    async fn remove_deletes_snapshot_before_metadata() {
        let backup = available_backup();
        let id = backup.id();
        let (service, repository, _, order) = service(backup, b"old".to_vec(), 3, false, false);

        service.remove(id).await.unwrap();

        assert!(repository.backup.lock().unwrap().is_none());
        assert_eq!(&*order.lock().unwrap(), &["snapshot", "metadata"]);
    }

    #[tokio::test]
    async fn failed_snapshot_removal_preserves_metadata_and_releases_lease() {
        let backup = available_backup();
        let id = backup.id();
        let (service, repository, _, _) = service(backup, b"old".to_vec(), 3, false, true);

        assert!(service.remove(id).await.is_err());

        assert_eq!(
            repository.backup.lock().unwrap().as_ref().unwrap().state(),
            BackupState::Available
        );
    }

    #[tokio::test]
    async fn open_and_restore_reject_snapshot_length_mismatch() {
        let backup = available_backup();
        let id = backup.id();
        let (service, repository, _, _) = service(backup, b"old".to_vec(), 4, false, false);

        assert!(matches!(
            service.open(id).await,
            Err(BackupLifecycleError::SnapshotLengthMismatch)
        ));
        assert!(matches!(
            service.restore(id).await,
            Err(BackupLifecycleError::SnapshotLengthMismatch)
        ));
        assert_eq!(
            repository.backup.lock().unwrap().as_ref().unwrap().state(),
            BackupState::Available
        );
    }

    #[tokio::test]
    async fn list_delegates_cursor_query_to_repository() {
        let backup = available_backup();
        let id = backup.id();
        let created_at = backup.created_at();
        let (service, _, _, _) = service(backup, b"old".to_vec(), 3, false, false);
        let query = BackupListQuery::new(
            Some(BackupListCursor {
                created_at,
                backup_id: id,
            }),
            10,
        )
        .unwrap();

        assert_eq!(service.list(query).await.unwrap().len(), 1);
    }

    #[test]
    fn rejects_zero_operation_lease() {
        let backup = available_backup();
        let (service, repository, target, _) = service(backup, b"old".to_vec(), 3, false, false);
        drop(service);
        let snapshots = Arc::new(MemorySnapshots {
            content: b"old".to_vec(),
            reported_length: 3,
            fail_remove: false,
            order: Arc::new(Mutex::new(Vec::new())),
        });

        assert!(
            BackupLifecycleService::new(
                repository,
                snapshots,
                target,
                Arc::new(FixedClock(now())),
                StdDuration::ZERO,
            )
            .is_err()
        );
    }
}
