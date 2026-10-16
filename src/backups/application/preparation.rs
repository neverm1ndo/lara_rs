use std::{sync::Arc, time::Duration as StdDuration};

use chrono::Duration;
use thiserror::Error;

use crate::{
    backups::{
        application::ports::{
            BackupClock, BackupDiffGenerator, BackupDiffInput, BackupIdGenerator, BackupRepository,
            BackupRepositoryError, BackupSnapshotStore, BackupSnapshotStoreError,
            BackupSnapshotWrite,
        },
        domain::{
            Backup, BackupAction, BackupDiff, BackupDiffSkipReason, BackupInitiatorId,
            BackupSnapshot, BackupSource, BackupState, BackupVersion, InvalidBackup,
            SnapshotCompression,
        },
    },
    shared::file_storage::{
        content::FileContentClassifier,
        guard::{
            BackupReceipt, BackupRequirement, BeforeFileMutation, BeforeFileMutationError,
            BeforeMutationFuture, FileMutationIntent, InvalidMutationPermit, MutationPermit,
            ReadFileSnapshotError,
        },
        mutation::FileMutationKind,
    },
};

/// Runtime policy for the synchronous pre-mutation backup workflow.
#[derive(Debug, Clone, Copy)]
pub struct BackupPreparationPolicy {
    lifetime: Duration,
    preparation_lease: Duration,
    compression: SnapshotCompression,
    compression_threshold_bytes: u64,
}

impl BackupPreparationPolicy {
    pub fn new(
        lifetime: StdDuration,
        preparation_lease: StdDuration,
        compression: SnapshotCompression,
        compression_threshold_bytes: u64,
    ) -> Result<Self, InvalidBackupPreparationPolicy> {
        if lifetime.is_zero() {
            return Err(InvalidBackupPreparationPolicy::Lifetime);
        }
        if preparation_lease.is_zero() || preparation_lease > lifetime {
            return Err(InvalidBackupPreparationPolicy::Lease);
        }
        if compression_threshold_bytes == 0 {
            return Err(InvalidBackupPreparationPolicy::CompressionThreshold);
        }

        Ok(Self {
            lifetime: Duration::from_std(lifetime)
                .map_err(|_| InvalidBackupPreparationPolicy::Lifetime)?,
            preparation_lease: Duration::from_std(preparation_lease)
                .map_err(|_| InvalidBackupPreparationPolicy::Lease)?,
            compression,
            compression_threshold_bytes,
        })
    }

    fn compression_for(self, size: u64) -> SnapshotCompression {
        if self.compression == SnapshotCompression::Gzip && size >= self.compression_threshold_bytes
        {
            SnapshotCompression::Gzip
        } else {
            SnapshotCompression::None
        }
    }
}

/// Adapter between the shared file-mutation protocol and the backups bounded
/// context. It does not know a filesystem root: source bytes are obtained only
/// through the verified capability carried by `FileMutationIntent`.
pub struct BackupPreparationService {
    repository: Arc<dyn BackupRepository>,
    snapshots: Arc<dyn BackupSnapshotStore>,
    diffs: Arc<dyn BackupDiffGenerator>,
    clock: Arc<dyn BackupClock>,
    ids: Arc<dyn BackupIdGenerator>,
    classifier: FileContentClassifier,
    policy: BackupPreparationPolicy,
}

impl BackupPreparationService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository: Arc<dyn BackupRepository>,
        snapshots: Arc<dyn BackupSnapshotStore>,
        diffs: Arc<dyn BackupDiffGenerator>,
        clock: Arc<dyn BackupClock>,
        ids: Arc<dyn BackupIdGenerator>,
        classifier: FileContentClassifier,
        policy: BackupPreparationPolicy,
    ) -> Self {
        Self {
            repository,
            snapshots,
            diffs,
            clock,
            ids,
            classifier,
            policy,
        }
    }

    async fn create_backup(
        &self,
        intent: &FileMutationIntent<'_>,
    ) -> Result<Option<BackupReceipt>, BackupPreparationError> {
        let kind = intent.request().operation().kind();
        let action = match BackupAction::try_from(kind) {
            Ok(action) => action,
            Err(InvalidBackup::UnsupportedMutation) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let current = intent
            .current_file()
            .ok_or(BackupPreparationError::MissingSource)?;
        let source =
            BackupSource::new(intent.request().namespace().clone(), current.path().clone())?;
        let initiated_by = parse_initiator(intent.request().actor().subject())?;

        if let Some(existing) = self
            .repository
            .find_by_mutation_id(intent.request().mutation_id())
            .await?
        {
            return existing_receipt(&existing, &source, action, initiated_by, current.revision())
                .map(Some);
        }

        let before = intent
            .read_current()
            .await?
            .ok_or(BackupPreparationError::MissingSource)?;
        let content_kind = self.classifier.classify(current.path(), &before);
        let now = self.clock.now();
        let expires_at = now
            .checked_add_signed(self.policy.lifetime)
            .ok_or(BackupPreparationError::TimeOverflow)?;
        let lease_expires_at = now
            .checked_add_signed(self.policy.preparation_lease)
            .ok_or(BackupPreparationError::TimeOverflow)?;
        let mut backup = Backup::prepare(
            self.ids.next_id(),
            intent.request().mutation_id(),
            source,
            action,
            initiated_by,
            current.revision().clone(),
            now,
            expires_at,
            lease_expires_at,
        )?;

        if let Err(error) = self.repository.insert(&backup).await {
            if error == BackupRepositoryError::AlreadyExists {
                let existing = self
                    .repository
                    .find_by_mutation_id(intent.request().mutation_id())
                    .await?
                    .ok_or(BackupPreparationError::DuplicateMutationUnavailable)?;
                return existing_receipt(
                    &existing,
                    backup.source(),
                    action,
                    initiated_by,
                    current.revision(),
                )
                .map(Some);
            }
            return Err(error.into());
        }

        let compression = self
            .policy
            .compression_for(u64::try_from(before.len()).unwrap_or(u64::MAX));
        let stored = match self
            .snapshots
            .persist(BackupSnapshotWrite {
                backup_id: backup.id(),
                content: &before,
                compression,
            })
            .await
        {
            Ok(stored) => stored,
            Err(error) => {
                self.mark_failed(&mut backup).await;
                return Err(error.into());
            }
        };

        let diff = match self
            .diffs
            .generate(BackupDiffInput {
                source: backup.source(),
                content_kind,
                before: &before,
                after: match kind {
                    FileMutationKind::Overwrite => intent.content().replacement(),
                    FileMutationKind::Delete => None,
                    FileMutationKind::Create | FileMutationKind::Rename => unreachable!(),
                },
            })
            .await
        {
            Ok(diff) => diff,
            Err(error) => {
                tracing::warn!(error = %error, backup_id = %backup.id(), "backup diff generation failed");
                BackupDiff::Skipped(BackupDiffSkipReason::GenerationFailed)
            }
        };
        let snapshot = BackupSnapshot::new(
            current.revision().clone(),
            stored.content_hash,
            content_kind,
            u64::try_from(before.len()).unwrap_or(u64::MAX),
            stored.stored_bytes,
            stored.compression,
        )?;
        backup.mark_available(snapshot, diff)?;
        self.repository
            .save(&backup, BackupVersion::initial())
            .await?;

        Ok(Some(receipt(&backup)?))
    }

    async fn mark_failed(&self, backup: &mut Backup) {
        if backup.fail_preparation().is_ok()
            && let Err(error) = self.repository.save(backup, BackupVersion::initial()).await
        {
            tracing::warn!(error = %error, backup_id = %backup.id(), "failed to mark backup preparation as failed");
        }
        if let Err(error) = self.snapshots.remove(backup.id()).await {
            tracing::warn!(error = %error, backup_id = %backup.id(), "failed to clean up incomplete backup snapshot");
        }
    }
}

impl BeforeFileMutation for BackupPreparationService {
    fn prepare<'a>(&'a self, intent: FileMutationIntent<'a>) -> BeforeMutationFuture<'a> {
        Box::pin(async move {
            if intent.backup_requirement() == BackupRequirement::Disabled {
                return MutationPermit::new(
                    intent.request(),
                    intent.current_file(),
                    None,
                    intent.backup_requirement(),
                )
                .map_err(Into::into);
            }

            let receipt = match self.create_backup(&intent).await {
                Ok(receipt) => receipt,
                Err(error) if intent.backup_requirement() == BackupRequirement::Optional => {
                    tracing::warn!(error = %error, mutation_id = %intent.request().mutation_id(), "optional file backup failed");
                    None
                }
                Err(error) => {
                    return Err(BeforeFileMutationError::Unavailable {
                        message: error.to_string(),
                    });
                }
            };

            MutationPermit::new(
                intent.request(),
                intent.current_file(),
                receipt,
                intent.backup_requirement(),
            )
            .map_err(Into::into)
        })
    }
}

fn parse_initiator(subject: &str) -> Result<BackupInitiatorId, BackupPreparationError> {
    let value = subject
        .parse::<i64>()
        .map_err(|_| BackupPreparationError::InvalidInitiator)?;
    BackupInitiatorId::new(value).map_err(|_| BackupPreparationError::InvalidInitiator)
}

fn existing_receipt(
    backup: &Backup,
    source: &BackupSource,
    action: BackupAction,
    initiated_by: BackupInitiatorId,
    source_revision: &crate::shared::file_storage::mutation::FileRevision,
) -> Result<BackupReceipt, BackupPreparationError> {
    if backup.source() != source
        || backup.action() != action
        || backup.initiated_by() != initiated_by
        || backup.source_revision() != source_revision
    {
        return Err(BackupPreparationError::MutationConflict);
    }
    if backup.state() != BackupState::Available {
        return Err(BackupPreparationError::DuplicateMutationUnavailable);
    }
    receipt(backup)
}

fn receipt(backup: &Backup) -> Result<BackupReceipt, BackupPreparationError> {
    BackupReceipt::new(
        backup.mutation_id(),
        backup.id().to_string(),
        backup.source_revision().clone(),
        backup.created_at(),
    )
    .map_err(BackupPreparationError::InvalidReceipt)
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidBackupPreparationPolicy {
    #[error("backup lifetime must be greater than zero and fit chrono duration")]
    Lifetime,
    #[error("backup preparation lease must be positive and not exceed lifetime")]
    Lease,
    #[error("backup compression threshold must be greater than zero")]
    CompressionThreshold,
}

#[derive(Debug, Error)]
pub enum BackupPreparationError {
    #[error("destructive mutation has no source snapshot")]
    MissingSource,
    #[error("mutation actor is not a valid positive user ID")]
    InvalidInitiator,
    #[error("backup timestamp overflow")]
    TimeOverflow,
    #[error("another backup with this mutation ID is incomplete")]
    DuplicateMutationUnavailable,
    #[error("mutation ID is already associated with different backup input")]
    MutationConflict,
    #[error(transparent)]
    Domain(#[from] InvalidBackup),
    #[error(transparent)]
    Repository(#[from] BackupRepositoryError),
    #[error(transparent)]
    Snapshot(#[from] BackupSnapshotStoreError),
    #[error(transparent)]
    Read(#[from] ReadFileSnapshotError),
    #[error("could not construct backup receipt: {0}")]
    InvalidReceipt(InvalidMutationPermit),
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use chrono::{DateTime, TimeZone, Utc};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        backups::{
            application::ports::{
                BackupDiffError, BackupDiffFuture, BackupListQuery, BackupRepositoryFuture,
                BackupSnapshotStoreFuture, OpenedBackupSnapshot, StoredBackupSnapshot,
            },
            domain::{BackupId, BackupState},
        },
        shared::file_storage::{
            guard::{FileSnapshot, FileSnapshotSource, ReadFileSnapshotFuture},
            mutation::{
                ContentHashAlgorithm, FileContentHash, FileMutationRequest, FileRevision,
                MutationActor, MutationId, StorageNamespace,
            },
            path::RelativeStoragePath,
        },
    };

    #[derive(Default)]
    struct MemoryRepository(Mutex<Vec<Backup>>);

    impl MemoryRepository {
        fn only(&self) -> Backup {
            self.0.lock().unwrap()[0].clone()
        }
    }

    impl BackupRepository for MemoryRepository {
        fn insert<'a>(&'a self, backup: &'a Backup) -> BackupRepositoryFuture<'a, ()> {
            Box::pin(async move {
                let mut values = self.0.lock().unwrap();
                if values
                    .iter()
                    .any(|value| value.mutation_id() == backup.mutation_id())
                {
                    return Err(BackupRepositoryError::AlreadyExists);
                }
                values.push(backup.clone());
                Ok(())
            })
        }

        fn find_by_id<'a>(
            &'a self,
            backup_id: BackupId,
        ) -> BackupRepositoryFuture<'a, Option<Backup>> {
            Box::pin(async move {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|value| value.id() == backup_id)
                    .cloned())
            })
        }

        fn find_by_mutation_id<'a>(
            &'a self,
            mutation_id: MutationId,
        ) -> BackupRepositoryFuture<'a, Option<Backup>> {
            Box::pin(async move {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|value| value.mutation_id() == mutation_id)
                    .cloned())
            })
        }

        fn list<'a>(&'a self, _query: BackupListQuery) -> BackupRepositoryFuture<'a, Vec<Backup>> {
            Box::pin(async move { Ok(self.0.lock().unwrap().clone()) })
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
            expected: BackupVersion,
        ) -> BackupRepositoryFuture<'a, ()> {
            Box::pin(async move {
                let mut values = self.0.lock().unwrap();
                let Some(value) = values.iter_mut().find(|value| value.id() == backup.id()) else {
                    return Err(BackupRepositoryError::ConcurrentModification);
                };
                if value.version() != expected {
                    return Err(BackupRepositoryError::ConcurrentModification);
                }
                *value = backup.clone();
                Ok(())
            })
        }

        fn delete<'a>(
            &'a self,
            backup_id: BackupId,
            expected: BackupVersion,
        ) -> BackupRepositoryFuture<'a, ()> {
            Box::pin(async move {
                let mut values = self.0.lock().unwrap();
                let Some(position) = values
                    .iter()
                    .position(|value| value.id() == backup_id && value.version() == expected)
                else {
                    return Err(BackupRepositoryError::ConcurrentModification);
                };
                values.remove(position);
                Ok(())
            })
        }
    }

    struct MemorySnapshots {
        writes: AtomicUsize,
        fail: bool,
    }

    impl BackupSnapshotStore for MemorySnapshots {
        fn persist<'a>(
            &'a self,
            write: BackupSnapshotWrite<'a>,
        ) -> BackupSnapshotStoreFuture<'a, StoredBackupSnapshot> {
            Box::pin(async move {
                self.writes.fetch_add(1, Ordering::SeqCst);
                if self.fail {
                    return Err(BackupSnapshotStoreError::Unavailable {
                        message: "offline".into(),
                    });
                }
                let hash = Sha256::digest(write.content);
                Ok(StoredBackupSnapshot {
                    stored_bytes: write.content.len() as u64,
                    content_hash: FileContentHash::new(
                        ContentHashAlgorithm::Sha256,
                        format!("{hash:x}"),
                    )
                    .unwrap(),
                    compression: write.compression,
                })
            })
        }

        fn open<'a>(
            &'a self,
            _backup_id: BackupId,
            _expected_hash: &'a FileContentHash,
            _compression: SnapshotCompression,
        ) -> BackupSnapshotStoreFuture<'a, OpenedBackupSnapshot> {
            Box::pin(async {
                Err(BackupSnapshotStoreError::Unavailable {
                    message: "unused".into(),
                })
            })
        }

        fn remove<'a>(&'a self, _backup_id: BackupId) -> BackupSnapshotStoreFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    struct PatchDiff;

    impl BackupDiffGenerator for PatchDiff {
        fn generate<'a>(&'a self, _input: BackupDiffInput<'a>) -> BackupDiffFuture<'a> {
            Box::pin(async { Ok(BackupDiff::DiffMatchPatch("@@ patch @@".into())) })
        }
    }

    struct FailingDiff;

    impl BackupDiffGenerator for FailingDiff {
        fn generate<'a>(&'a self, _input: BackupDiffInput<'a>) -> BackupDiffFuture<'a> {
            Box::pin(async {
                Err(BackupDiffError::Failed {
                    message: "worker".into(),
                })
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

    #[derive(Clone, Copy)]
    struct FixedId(BackupId);

    impl BackupIdGenerator for FixedId {
        fn next_id(&self) -> BackupId {
            self.0
        }
    }

    struct Bytes(Vec<u8>);

    impl FileSnapshotSource for Bytes {
        fn read_verified<'a>(&'a self, _snapshot: &'a FileSnapshot) -> ReadFileSnapshotFuture<'a> {
            Box::pin(async move { Ok(self.0.clone()) })
        }
    }

    fn service(
        repository: Arc<MemoryRepository>,
        snapshots: Arc<MemorySnapshots>,
        diffs: Arc<dyn BackupDiffGenerator>,
    ) -> BackupPreparationService {
        BackupPreparationService::new(
            repository,
            snapshots,
            diffs,
            Arc::new(FixedClock(Utc.timestamp_opt(1_700_000_100, 0).unwrap())),
            Arc::new(FixedId(BackupId::new())),
            FileContentClassifier::new(["amx"], ["omp-server"]).unwrap(),
            BackupPreparationPolicy::new(
                StdDuration::from_secs(3600),
                StdDuration::from_secs(60),
                SnapshotCompression::Gzip,
                1,
            )
            .unwrap(),
        )
    }

    fn request() -> FileMutationRequest {
        FileMutationRequest::overwrite(
            StorageNamespace::new("configuration").unwrap(),
            MutationActor::new("42", Some("session".into())).unwrap(),
            RelativeStoragePath::new("server.cfg").unwrap(),
            None,
        )
        .unwrap()
    }

    fn snapshot() -> FileSnapshot {
        FileSnapshot::new(
            RelativeStoragePath::new("server.cfg").unwrap(),
            FileRevision::from_metadata(3, Utc.timestamp_opt(1_700_000_000, 0).unwrap()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn required_backup_persists_snapshot_and_metadata_before_permitting_mutation() {
        let repository = Arc::new(MemoryRepository::default());
        let snapshots = Arc::new(MemorySnapshots {
            writes: AtomicUsize::new(0),
            fail: false,
        });
        let service = service(repository.clone(), snapshots.clone(), Arc::new(PatchDiff));
        let request = request();
        let snapshot = snapshot();
        let source = Bytes(b"old".to_vec());
        let replacement = b"new";
        let intent = FileMutationIntent::new(
            &request,
            Some(&snapshot),
            &source,
            Some(replacement),
            BackupRequirement::Required,
        );

        let permit = service.prepare(intent).await.unwrap();
        let backup = repository.only();

        assert_eq!(snapshots.writes.load(Ordering::SeqCst), 1);
        assert_eq!(backup.state(), BackupState::Available);
        assert_eq!(backup.initiated_by().get(), 42);
        assert_eq!(
            permit.backup_receipt().unwrap().backup_id(),
            backup.id().to_string()
        );
    }

    #[tokio::test]
    async fn repeated_mutation_reuses_available_backup_without_rewriting_snapshot() {
        let repository = Arc::new(MemoryRepository::default());
        let snapshots = Arc::new(MemorySnapshots {
            writes: AtomicUsize::new(0),
            fail: false,
        });
        let service = service(repository, snapshots.clone(), Arc::new(PatchDiff));
        let request = request();
        let snapshot = snapshot();
        let source = Bytes(b"old".to_vec());

        for _ in 0..2 {
            let intent = FileMutationIntent::new(
                &request,
                Some(&snapshot),
                &source,
                Some(b"new"),
                BackupRequirement::Required,
            );
            assert!(service.prepare(intent).await.is_ok());
        }

        assert_eq!(snapshots.writes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn required_snapshot_failure_blocks_mutation_but_optional_failure_does_not() {
        for (requirement, should_fail) in [
            (BackupRequirement::Required, true),
            (BackupRequirement::Optional, false),
        ] {
            let repository = Arc::new(MemoryRepository::default());
            let snapshots = Arc::new(MemorySnapshots {
                writes: AtomicUsize::new(0),
                fail: true,
            });
            let service = service(repository.clone(), snapshots, Arc::new(PatchDiff));
            let request = request();
            let snapshot = snapshot();
            let source = Bytes(b"old".to_vec());
            let intent = FileMutationIntent::new(
                &request,
                Some(&snapshot),
                &source,
                Some(b"new"),
                requirement,
            );

            let result = service.prepare(intent).await;
            assert_eq!(result.is_err(), should_fail);
            assert_eq!(repository.only().state(), BackupState::PreparationFailed);
        }
    }

    #[tokio::test]
    async fn diff_failure_keeps_full_snapshot_available_with_explicit_skip_reason() {
        let repository = Arc::new(MemoryRepository::default());
        let snapshots = Arc::new(MemorySnapshots {
            writes: AtomicUsize::new(0),
            fail: false,
        });
        let service = service(repository.clone(), snapshots, Arc::new(FailingDiff));
        let request = request();
        let snapshot = snapshot();
        let source = Bytes(b"old".to_vec());
        let intent = FileMutationIntent::new(
            &request,
            Some(&snapshot),
            &source,
            Some(b"new"),
            BackupRequirement::Required,
        );

        service.prepare(intent).await.unwrap();

        assert_eq!(
            repository.only().diff(),
            Some(&BackupDiff::Skipped(BackupDiffSkipReason::GenerationFailed))
        );
    }

    #[test]
    fn validates_preparation_policy() {
        assert!(
            BackupPreparationPolicy::new(
                StdDuration::ZERO,
                StdDuration::from_secs(1),
                SnapshotCompression::None,
                1,
            )
            .is_err()
        );
        assert!(
            BackupPreparationPolicy::new(
                StdDuration::from_secs(1),
                StdDuration::from_secs(2),
                SnapshotCompression::None,
                1,
            )
            .is_err()
        );
        assert!(
            BackupPreparationPolicy::new(
                StdDuration::from_secs(2),
                StdDuration::from_secs(1),
                SnapshotCompression::None,
                0,
            )
            .is_err()
        );
    }
}
