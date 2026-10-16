use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use crate::{
    backups::{
        application::ports::{BackupRestoreError, BackupRestoreTarget},
        domain::BackupSource,
    },
    shared::file_storage::{
        coordinator::{FileMutationCoordinator, FileMutationCoordinatorError, FileMutationPayload},
        guard::{BackupRequirement, NoBackupProvider},
        local::LocalFileStorage,
        mutation::{FileMutationRequest, MutationActor, StorageNamespace},
        path::RelativeStoragePath,
    },
};

type PathPolicy = Arc<dyn Fn(&RelativeStoragePath) -> bool + Send + Sync>;

#[derive(Clone)]
struct NamespaceTarget {
    coordinator: FileMutationCoordinator,
    namespace: StorageNamespace,
    path_policy: PathPolicy,
}

/// Routes restore requests to capability-scoped storages. Registering a
/// namespace is an explicit composition-root decision; persisted absolute
/// paths can never escape through this adapter.
#[derive(Clone, Default)]
pub struct CapabilityBackupRestoreTarget {
    targets: HashMap<String, NamespaceTarget>,
}

impl CapabilityBackupRestoreTarget {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        mut self,
        namespace: StorageNamespace,
        storage: LocalFileStorage,
        path_policy: impl Fn(&RelativeStoragePath) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.targets.insert(
            namespace.to_string(),
            NamespaceTarget {
                coordinator: FileMutationCoordinator::new(storage, Arc::new(NoBackupProvider)),
                namespace,
                path_policy: Arc::new(path_policy),
            },
        );
        self
    }
}

impl BackupRestoreTarget for CapabilityBackupRestoreTarget {
    fn restore<'a>(
        &'a self,
        source: &'a BackupSource,
        content: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), BackupRestoreError>> + Send + 'a>> {
        Box::pin(async move {
            let target = self
                .targets
                .get(source.namespace().as_str())
                .ok_or(BackupRestoreError::UnknownNamespace)?;
            if !(target.path_policy)(source.path()) {
                return Err(BackupRestoreError::InvalidPath {
                    path: source.path().clone(),
                });
            }
            let actor =
                MutationActor::new("backup-restore", None).expect("constant actor is valid");
            let request = FileMutationRequest::overwrite(
                target.namespace.clone(),
                actor,
                source.path().clone(),
                None,
            )
            .map_err(|_| BackupRestoreError::InvalidPath {
                path: source.path().clone(),
            })?;
            target
                .coordinator
                .execute(
                    &request,
                    FileMutationPayload::Content(content.to_vec()),
                    BackupRequirement::Disabled,
                )
                .await
                .map_err(|error| map_restore_error(error, source.path()))?;
            Ok(())
        })
    }
}

fn map_restore_error(
    error: FileMutationCoordinatorError,
    path: &RelativeStoragePath,
) -> BackupRestoreError {
    match error {
        FileMutationCoordinatorError::ConcurrentModification => {
            BackupRestoreError::ConcurrentModification
        }
        FileMutationCoordinatorError::Storage(
            crate::shared::file_storage::local::LocalFileStorageError::Io(error),
        ) if error.kind() == std::io::ErrorKind::NotFound => {
            BackupRestoreError::InvalidPath { path: path.clone() }
        }
        FileMutationCoordinatorError::PayloadMismatch
        | FileMutationCoordinatorError::ContentTooLarge { .. }
        | FileMutationCoordinatorError::Guard(_)
        | FileMutationCoordinatorError::InvalidPermit(_)
        | FileMutationCoordinatorError::Storage(_) => BackupRestoreError::Unavailable {
            message: error.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use uuid::Uuid;

    use super::*;
    use crate::shared::file_storage::local::FileStorageLimits;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lara-restore-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn namespace(value: &str) -> StorageNamespace {
        StorageNamespace::new(value).unwrap()
    }

    fn source(namespace: &str, path: &str) -> BackupSource {
        BackupSource::new(
            self::namespace(namespace),
            RelativeStoragePath::new(path).unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn restores_only_registered_and_policy_allowed_relative_paths() {
        let directory = TestDirectory::new();
        fs::write(directory.0.join("race.map"), b"current").unwrap();
        fs::write(directory.0.join("notes.txt"), b"keep").unwrap();
        let storage =
            LocalFileStorage::open(&directory.0, FileStorageLimits::new(8, 100, 1024).unwrap())
                .await
                .unwrap();
        let target =
            CapabilityBackupRestoreTarget::new().register(namespace("maps"), storage, |path| {
                path.file_name().is_some_and(|name| name.ends_with(".map"))
            });

        target
            .restore(&source("maps", "race.map"), b"restored")
            .await
            .unwrap();
        assert_eq!(fs::read(directory.0.join("race.map")).unwrap(), b"restored");

        assert!(matches!(
            target.restore(&source("maps", "notes.txt"), b"bad").await,
            Err(BackupRestoreError::InvalidPath { .. })
        ));
        assert_eq!(fs::read(directory.0.join("notes.txt")).unwrap(), b"keep");
        assert_eq!(
            target
                .restore(&source("configuration", "server.cfg"), b"bad")
                .await,
            Err(BackupRestoreError::UnknownNamespace)
        );
    }

    #[tokio::test]
    async fn maps_missing_restore_destination_to_invalid_path() {
        let directory = TestDirectory::new();
        let storage =
            LocalFileStorage::open(&directory.0, FileStorageLimits::new(8, 100, 1024).unwrap())
                .await
                .unwrap();
        let target =
            CapabilityBackupRestoreTarget::new().register(namespace("maps"), storage, |_| true);

        assert!(matches!(
            target
                .restore(&source("maps", "missing.map"), b"data")
                .await,
            Err(BackupRestoreError::InvalidPath { .. })
        ));
    }
}
