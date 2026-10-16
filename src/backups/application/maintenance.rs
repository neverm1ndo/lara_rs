use std::{sync::Arc, time::Duration as StdDuration};

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;
use tokio::task::JoinSet;

use crate::backups::{
    application::ports::{
        BackupClock, BackupRepository, BackupRepositoryError, BackupSnapshotStore,
    },
    domain::{Backup, BackupState, InvalidBackup},
};

#[derive(Debug, Clone, Copy)]
pub struct BackupMaintenancePolicy {
    batch_size: usize,
    max_concurrent_deletions: usize,
    operation_lease: Duration,
}

impl BackupMaintenancePolicy {
    pub fn new(
        batch_size: usize,
        max_concurrent_deletions: usize,
        operation_lease: StdDuration,
    ) -> Result<Self, InvalidBackupMaintenancePolicy> {
        if batch_size == 0 {
            return Err(InvalidBackupMaintenancePolicy::BatchSize);
        }
        if max_concurrent_deletions == 0 {
            return Err(InvalidBackupMaintenancePolicy::Concurrency);
        }
        if operation_lease.is_zero() {
            return Err(InvalidBackupMaintenancePolicy::OperationLease);
        }

        Ok(Self {
            batch_size,
            max_concurrent_deletions,
            operation_lease: Duration::from_std(operation_lease)
                .map_err(|_| InvalidBackupMaintenancePolicy::OperationLease)?,
        })
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BackupMaintenanceReport {
    pub expired_scanned: usize,
    pub expired_deleted: usize,
    pub stale_preparations_scanned: usize,
    pub stale_preparations_failed: usize,
    pub stale_restores_released: usize,
    pub stale_deletions_completed: usize,
    pub conflicts: usize,
    pub failures: usize,
}

pub struct BackupMaintenanceService {
    repository: Arc<dyn BackupRepository>,
    snapshots: Arc<dyn BackupSnapshotStore>,
    clock: Arc<dyn BackupClock>,
    policy: BackupMaintenancePolicy,
}

impl BackupMaintenanceService {
    pub fn new(
        repository: Arc<dyn BackupRepository>,
        snapshots: Arc<dyn BackupSnapshotStore>,
        clock: Arc<dyn BackupClock>,
        policy: BackupMaintenancePolicy,
    ) -> Self {
        Self {
            repository,
            snapshots,
            clock,
            policy,
        }
    }

    /// Executes one bounded maintenance cycle. Individual item failures are
    /// reported but do not prevent independent backups from being processed.
    pub async fn run_once(&self) -> Result<BackupMaintenanceReport, BackupMaintenanceError> {
        let now = self.clock.now();
        let lease_expires_at = now
            .checked_add_signed(self.policy.operation_lease)
            .ok_or(BackupMaintenanceError::TimeOverflow)?;
        let mut report = BackupMaintenanceReport::default();

        let stale_preparations = self
            .repository
            .find_stale_preparations(now, self.policy.batch_size)
            .await?;
        report.stale_preparations_scanned = stale_preparations.len();
        for backup in stale_preparations {
            record(
                fail_stale_preparation(self.repository.clone(), self.snapshots.clone(), backup)
                    .await,
                &mut report,
                CompletedKind::StalePreparation,
            );
        }

        let stale_operations = self
            .repository
            .find_stale_operations(now, self.policy.batch_size)
            .await?;
        for backup in stale_operations {
            let state = backup.state();
            let outcome = match state {
                BackupState::Restoring { .. } => {
                    release_stale_restore(self.repository.clone(), backup).await
                }
                BackupState::Deleting { .. } => {
                    resume_deletion(self.repository.clone(), self.snapshots.clone(), backup).await
                }
                _ => WorkOutcome::Failed,
            };
            match state {
                BackupState::Restoring { .. } => {
                    record(outcome, &mut report, CompletedKind::StaleRestore)
                }
                BackupState::Deleting { .. } => {
                    record(outcome, &mut report, CompletedKind::StaleDeletion)
                }
                _ => report.failures += 1,
            }
        }

        let expired = self
            .repository
            .find_expired(now, self.policy.batch_size)
            .await?;
        report.expired_scanned = expired.len();
        let mut pending = expired.into_iter();
        loop {
            let mut tasks = JoinSet::new();
            for backup in pending.by_ref().take(self.policy.max_concurrent_deletions) {
                let repository = self.repository.clone();
                let snapshots = self.snapshots.clone();
                tasks.spawn(async move {
                    delete_expired(repository, snapshots, backup, now, lease_expires_at).await
                });
            }
            if tasks.is_empty() {
                break;
            }
            while let Some(result) = tasks.join_next().await {
                let outcome = match result {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        tracing::warn!(error = %error, "backup maintenance task failed to join");
                        WorkOutcome::Failed
                    }
                };
                record(outcome, &mut report, CompletedKind::ExpiredDeletion);
            }
        }

        Ok(report)
    }
}

async fn fail_stale_preparation(
    repository: Arc<dyn BackupRepository>,
    snapshots: Arc<dyn BackupSnapshotStore>,
    mut backup: Backup,
) -> WorkOutcome {
    let expected = backup.version();
    if backup.fail_preparation().is_err() {
        return WorkOutcome::Failed;
    }
    if let Err(error) = repository.save(&backup, expected).await {
        return repository_outcome(error);
    }
    match snapshots.remove(backup.id()).await {
        Ok(()) => WorkOutcome::Completed,
        Err(error) => {
            tracing::warn!(error = %error, backup_id = %backup.id(), "failed to remove stale preparation snapshot");
            WorkOutcome::Failed
        }
    }
}

async fn release_stale_restore(
    repository: Arc<dyn BackupRepository>,
    mut backup: Backup,
) -> WorkOutcome {
    let expected = backup.version();
    if backup.release_operation().is_err() {
        return WorkOutcome::Failed;
    }
    match repository.save(&backup, expected).await {
        Ok(()) => WorkOutcome::Completed,
        Err(error) => repository_outcome(error),
    }
}

async fn resume_deletion(
    repository: Arc<dyn BackupRepository>,
    snapshots: Arc<dyn BackupSnapshotStore>,
    backup: Backup,
) -> WorkOutcome {
    if let Err(error) = snapshots.remove(backup.id()).await {
        tracing::warn!(error = %error, backup_id = %backup.id(), "failed to resume backup snapshot deletion");
        return WorkOutcome::Failed;
    }
    match repository.delete(backup.id(), backup.version()).await {
        Ok(()) => WorkOutcome::Completed,
        Err(error) => repository_outcome(error),
    }
}

async fn delete_expired(
    repository: Arc<dyn BackupRepository>,
    snapshots: Arc<dyn BackupSnapshotStore>,
    mut backup: Backup,
    now: DateTime<Utc>,
    lease_expires_at: DateTime<Utc>,
) -> WorkOutcome {
    let expected = backup.version();
    if let Err(error) = backup.begin_deletion(now, lease_expires_at) {
        tracing::warn!(error = %error, backup_id = %backup.id(), "failed to reserve expired backup deletion");
        return WorkOutcome::Failed;
    }
    if let Err(error) = repository.save(&backup, expected).await {
        return repository_outcome(error);
    }
    resume_deletion(repository, snapshots, backup).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkOutcome {
    Completed,
    Conflict,
    Failed,
}

fn repository_outcome(error: BackupRepositoryError) -> WorkOutcome {
    if error == BackupRepositoryError::ConcurrentModification {
        WorkOutcome::Conflict
    } else {
        tracing::warn!(error = %error, "backup maintenance repository operation failed");
        WorkOutcome::Failed
    }
}

#[derive(Debug, Clone, Copy)]
enum CompletedKind {
    ExpiredDeletion,
    StalePreparation,
    StaleRestore,
    StaleDeletion,
}

fn record(outcome: WorkOutcome, report: &mut BackupMaintenanceReport, kind: CompletedKind) {
    match outcome {
        WorkOutcome::Completed => match kind {
            CompletedKind::ExpiredDeletion => report.expired_deleted += 1,
            CompletedKind::StalePreparation => report.stale_preparations_failed += 1,
            CompletedKind::StaleRestore => report.stale_restores_released += 1,
            CompletedKind::StaleDeletion => report.stale_deletions_completed += 1,
        },
        WorkOutcome::Conflict => report.conflicts += 1,
        WorkOutcome::Failed => report.failures += 1,
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidBackupMaintenancePolicy {
    #[error("backup cleanup batch size must be greater than zero")]
    BatchSize,
    #[error("backup cleanup concurrency must be greater than zero")]
    Concurrency,
    #[error("backup operation lease must be greater than zero and fit chrono duration")]
    OperationLease,
}

#[derive(Debug, Error)]
pub enum BackupMaintenanceError {
    #[error("backup maintenance timestamp overflow")]
    TimeOverflow,
    #[error(transparent)]
    Repository(#[from] BackupRepositoryError),
    #[error(transparent)]
    Domain(#[from] InvalidBackup),
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use chrono::TimeZone;

    use super::*;
    use crate::{
        backups::{
            application::ports::{
                BackupListQuery, BackupRepositoryFuture, BackupSnapshotStoreError,
                BackupSnapshotStoreFuture, BackupSnapshotWrite, OpenedBackupSnapshot,
                StoredBackupSnapshot,
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

    #[derive(Default)]
    struct MemoryRepository(Mutex<Vec<Backup>>);

    impl BackupRepository for MemoryRepository {
        fn insert<'a>(&'a self, backup: &'a Backup) -> BackupRepositoryFuture<'a, ()> {
            Box::pin(async move {
                self.0.lock().unwrap().push(backup.clone());
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
                    .find(|backup| backup.id() == backup_id)
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
                    .find(|backup| backup.mutation_id() == mutation_id)
                    .cloned())
            })
        }

        fn list<'a>(&'a self, _query: BackupListQuery) -> BackupRepositoryFuture<'a, Vec<Backup>> {
            Box::pin(async move { Ok(self.0.lock().unwrap().clone()) })
        }

        fn find_expired<'a>(
            &'a self,
            at: DateTime<Utc>,
            limit: usize,
        ) -> BackupRepositoryFuture<'a, Vec<Backup>> {
            Box::pin(async move {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|backup| {
                        backup.expires_at() <= at
                            && matches!(
                                backup.state(),
                                BackupState::Available | BackupState::PreparationFailed
                            )
                    })
                    .take(limit)
                    .cloned()
                    .collect())
            })
        }

        fn find_stale_preparations<'a>(
            &'a self,
            at: DateTime<Utc>,
            limit: usize,
        ) -> BackupRepositoryFuture<'a, Vec<Backup>> {
            Box::pin(async move {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|backup| {
                        matches!(backup.state(), BackupState::Preparing { .. })
                            && backup.has_expired_lease(at)
                    })
                    .take(limit)
                    .cloned()
                    .collect())
            })
        }

        fn find_stale_operations<'a>(
            &'a self,
            at: DateTime<Utc>,
            limit: usize,
        ) -> BackupRepositoryFuture<'a, Vec<Backup>> {
            Box::pin(async move {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|backup| {
                        matches!(
                            backup.state(),
                            BackupState::Restoring { .. } | BackupState::Deleting { .. }
                        ) && backup.has_expired_lease(at)
                    })
                    .take(limit)
                    .cloned()
                    .collect())
            })
        }

        fn save<'a>(
            &'a self,
            backup: &'a Backup,
            expected: crate::backups::domain::BackupVersion,
        ) -> BackupRepositoryFuture<'a, ()> {
            Box::pin(async move {
                let mut values = self.0.lock().unwrap();
                let Some(current) = values.iter_mut().find(|value| value.id() == backup.id())
                else {
                    return Err(BackupRepositoryError::ConcurrentModification);
                };
                if current.version() != expected {
                    return Err(BackupRepositoryError::ConcurrentModification);
                }
                *current = backup.clone();
                Ok(())
            })
        }

        fn delete<'a>(
            &'a self,
            backup_id: BackupId,
            expected: crate::backups::domain::BackupVersion,
        ) -> BackupRepositoryFuture<'a, ()> {
            Box::pin(async move {
                let mut values = self.0.lock().unwrap();
                let Some(index) = values
                    .iter()
                    .position(|value| value.id() == backup_id && value.version() == expected)
                else {
                    return Err(BackupRepositoryError::ConcurrentModification);
                };
                values.remove(index);
                Ok(())
            })
        }
    }

    struct MemorySnapshots {
        removed: Mutex<Vec<BackupId>>,
        fail: bool,
    }

    impl BackupSnapshotStore for MemorySnapshots {
        fn persist<'a>(
            &'a self,
            _write: BackupSnapshotWrite<'a>,
        ) -> BackupSnapshotStoreFuture<'a, StoredBackupSnapshot> {
            Box::pin(async { unreachable!() })
        }

        fn open<'a>(
            &'a self,
            _backup_id: BackupId,
            _expected_hash: &'a FileContentHash,
            _compression: SnapshotCompression,
        ) -> BackupSnapshotStoreFuture<'a, OpenedBackupSnapshot> {
            Box::pin(async { unreachable!() })
        }

        fn remove<'a>(&'a self, backup_id: BackupId) -> BackupSnapshotStoreFuture<'a, ()> {
            Box::pin(async move {
                if self.fail {
                    return Err(BackupSnapshotStoreError::Unavailable {
                        message: "disk".into(),
                    });
                }
                self.removed.lock().unwrap().push(backup_id);
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

    fn base() -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000, 0).unwrap()
    }

    fn prepared(expires_at: DateTime<Utc>, lease: DateTime<Utc>) -> Backup {
        Backup::prepare(
            BackupId::new(),
            MutationId::new(),
            BackupSource::new(
                StorageNamespace::new("configuration").unwrap(),
                RelativeStoragePath::new("server.cfg").unwrap(),
            )
            .unwrap(),
            BackupAction::Overwrite,
            BackupInitiatorId::new(42).unwrap(),
            FileRevision::from_metadata(3, base()),
            base(),
            expires_at,
            lease,
        )
        .unwrap()
    }

    fn available(expires_at: DateTime<Utc>) -> Backup {
        let mut backup = prepared(expires_at, base() + Duration::seconds(30));
        let revision = backup.source_revision().clone();
        backup
            .mark_available(
                BackupSnapshot::new(
                    revision,
                    FileContentHash::new(ContentHashAlgorithm::Sha256, "00".repeat(32)).unwrap(),
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
        backups: Vec<Backup>,
        snapshot_failure: bool,
    ) -> (
        BackupMaintenanceService,
        Arc<MemoryRepository>,
        Arc<MemorySnapshots>,
    ) {
        let repository = Arc::new(MemoryRepository(Mutex::new(backups)));
        let snapshots = Arc::new(MemorySnapshots {
            removed: Mutex::new(Vec::new()),
            fail: snapshot_failure,
        });
        let service = BackupMaintenanceService::new(
            repository.clone(),
            snapshots.clone(),
            Arc::new(FixedClock(base() + Duration::minutes(5))),
            BackupMaintenancePolicy::new(20, 2, StdDuration::from_secs(60)).unwrap(),
        );
        (service, repository, snapshots)
    }

    #[tokio::test]
    async fn cycle_cleans_expired_and_recovers_each_stale_state() {
        let expired = available(base() + Duration::minutes(1));
        let expired_id = expired.id();
        let stale_preparing = prepared(base() + Duration::hours(1), base() + Duration::minutes(1));
        let preparation_id = stale_preparing.id();
        let mut stale_restore = available(base() + Duration::hours(1));
        stale_restore
            .begin_restore(base() + Duration::minutes(1), base() + Duration::minutes(2))
            .unwrap();
        let restore_id = stale_restore.id();
        let mut stale_deletion = available(base() + Duration::hours(1));
        stale_deletion
            .begin_deletion(base() + Duration::minutes(1), base() + Duration::minutes(2))
            .unwrap();
        let deletion_id = stale_deletion.id();
        let (service, repository, snapshots) = service(
            vec![expired, stale_preparing, stale_restore, stale_deletion],
            false,
        );

        let report = service.run_once().await.unwrap();

        assert_eq!(report.expired_deleted, 1);
        assert_eq!(report.stale_preparations_failed, 1);
        assert_eq!(report.stale_restores_released, 1);
        assert_eq!(report.stale_deletions_completed, 1);
        assert_eq!(report.conflicts, 0);
        assert_eq!(report.failures, 0);
        let values = repository.0.lock().unwrap();
        assert!(!values.iter().any(|backup| backup.id() == expired_id));
        assert!(!values.iter().any(|backup| backup.id() == deletion_id));
        assert_eq!(
            values
                .iter()
                .find(|backup| backup.id() == preparation_id)
                .unwrap()
                .state(),
            BackupState::PreparationFailed
        );
        assert_eq!(
            values
                .iter()
                .find(|backup| backup.id() == restore_id)
                .unwrap()
                .state(),
            BackupState::Available
        );
        assert_eq!(snapshots.removed.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn failed_file_removal_leaves_reserved_deletion_for_a_later_cycle() {
        let expired = available(base() + Duration::minutes(1));
        let id = expired.id();
        let (service, repository, _) = service(vec![expired], true);

        let report = service.run_once().await.unwrap();

        assert_eq!(report.expired_deleted, 0);
        assert_eq!(report.failures, 1);
        assert!(matches!(
            repository
                .0
                .lock()
                .unwrap()
                .iter()
                .find(|backup| backup.id() == id)
                .unwrap()
                .state(),
            BackupState::Deleting { .. }
        ));
    }

    #[test]
    fn validates_maintenance_policy() {
        assert!(BackupMaintenancePolicy::new(0, 1, StdDuration::from_secs(1)).is_err());
        assert!(BackupMaintenancePolicy::new(1, 0, StdDuration::from_secs(1)).is_err());
        assert!(BackupMaintenancePolicy::new(1, 1, StdDuration::ZERO).is_err());
    }
}
