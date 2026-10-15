use std::sync::Arc;

use chrono::Utc;
use thiserror::Error;

use super::{
    event::FileChanged,
    guard::{
        BackupRequirement, BeforeFileMutation, BeforeFileMutationError, FileSnapshot,
        InvalidMutationPermit, MutationPermit,
    },
    local::{LocalFileStorage, LocalFileStorageError},
    mutation::{FileMutationOperation, FileMutationRequest, FileRevision},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileMutationPayload {
    None,
    Content(Vec<u8>),
}

impl FileMutationPayload {
    fn content(&self) -> Option<&[u8]> {
        match self {
            Self::None => None,
            Self::Content(content) => Some(content),
        }
    }
}

/// Runs the full mutation lifecycle: observe, prepare/backup, verify again,
/// mutate, and finally produce the domain event.
#[derive(Clone)]
pub struct FileMutationCoordinator {
    storage: LocalFileStorage,
    before_mutation: Arc<dyn BeforeFileMutation>,
}

impl FileMutationCoordinator {
    pub fn new(storage: LocalFileStorage, before_mutation: Arc<dyn BeforeFileMutation>) -> Self {
        Self {
            storage,
            before_mutation,
        }
    }

    pub async fn execute(
        &self,
        request: &FileMutationRequest,
        payload: FileMutationPayload,
        backup_requirement: BackupRequirement,
    ) -> Result<FileChanged, FileMutationCoordinatorError> {
        validate_payload(
            request.operation(),
            &payload,
            self.storage.limits().max_stream_size_bytes,
        )?;

        let initial_snapshot = self.snapshot_for(request.operation()).await?;
        let permit = self
            .before_mutation
            .prepare(request, initial_snapshot.as_ref(), backup_requirement)
            .await?;

        if permit.mutation_id() != request.mutation_id() {
            return Err(FileMutationCoordinatorError::InvalidPermit(
                InvalidMutationPermit::PermitMutationMismatch,
            ));
        }

        self.verify_unchanged(request.operation(), &permit).await?;

        let previous_revision = initial_snapshot
            .as_ref()
            .map(|snapshot| snapshot.revision().clone());
        let current_revision = self.apply(request.operation(), payload.content()).await?;

        Ok(FileChanged::new(
            request.mutation_id(),
            request.namespace().clone(),
            request.actor().clone(),
            Utc::now(),
            request.operation().kind(),
            request.operation().source().cloned(),
            request.operation().destination().cloned(),
            previous_revision,
            current_revision,
            permit.backup_receipt().cloned(),
        ))
    }

    async fn snapshot_for(
        &self,
        operation: &FileMutationOperation,
    ) -> Result<Option<FileSnapshot>, FileMutationCoordinatorError> {
        let Some(source) = operation.source() else {
            if let Some(destination) = operation.destination() {
                self.storage.ensure_absent(destination).await?;
            }
            return Ok(None);
        };

        let revision = self.storage.file_revision(source).await?;
        Ok(Some(FileSnapshot::new(source.clone(), revision)?))
    }

    async fn verify_unchanged(
        &self,
        operation: &FileMutationOperation,
        permit: &MutationPermit,
    ) -> Result<(), FileMutationCoordinatorError> {
        match operation.source() {
            Some(source) => {
                let current = self.storage.file_revision(source).await?;
                if permit.expected_revision() != Some(&current) {
                    return Err(FileMutationCoordinatorError::ConcurrentModification);
                }
            }
            None => {
                let destination = operation
                    .destination()
                    .expect("validated create operation has a destination");
                self.storage.ensure_absent(destination).await?;
                if permit.expected_revision().is_some() {
                    return Err(FileMutationCoordinatorError::ConcurrentModification);
                }
            }
        }

        if let FileMutationOperation::Rename { destination, .. } = operation {
            self.storage.ensure_absent(destination).await?;
        }

        Ok(())
    }

    async fn apply(
        &self,
        operation: &FileMutationOperation,
        content: Option<&[u8]>,
    ) -> Result<Option<FileRevision>, LocalFileStorageError> {
        match operation {
            FileMutationOperation::Create { path } => {
                self.storage
                    .create_file(path, content.expect("validated content"))
                    .await?;
                self.storage.file_revision(path).await.map(Some)
            }
            FileMutationOperation::Overwrite { path, .. } => {
                self.storage
                    .overwrite_file(path, content.expect("validated content"))
                    .await?;
                self.storage.file_revision(path).await.map(Some)
            }
            FileMutationOperation::Delete { path, .. } => {
                self.storage.delete_file(path).await?;
                Ok(None)
            }
            FileMutationOperation::Rename {
                source,
                destination,
                ..
            } => {
                self.storage.rename_file(source, destination).await?;
                self.storage.file_revision(destination).await.map(Some)
            }
        }
    }
}

fn validate_payload(
    operation: &FileMutationOperation,
    payload: &FileMutationPayload,
    maximum_size: u64,
) -> Result<(), FileMutationCoordinatorError> {
    let needs_content = matches!(
        operation,
        FileMutationOperation::Create { .. } | FileMutationOperation::Overwrite { .. }
    );
    if needs_content != payload.content().is_some() {
        return Err(FileMutationCoordinatorError::PayloadMismatch);
    }
    if payload
        .content()
        .is_some_and(|content| content.len() as u64 > maximum_size)
    {
        return Err(FileMutationCoordinatorError::ContentTooLarge { maximum_size });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum FileMutationCoordinatorError {
    #[error("mutation payload does not match its operation")]
    PayloadMismatch,
    #[error("mutation content exceeds the {maximum_size}-byte storage limit")]
    ContentTooLarge { maximum_size: u64 },
    #[error("file changed while its mutation was being prepared")]
    ConcurrentModification,
    #[error(transparent)]
    Guard(#[from] BeforeFileMutationError),
    #[error(transparent)]
    InvalidPermit(#[from] InvalidMutationPermit),
    #[error(transparent)]
    Storage(#[from] LocalFileStorageError),
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::shared::file_storage::{
        guard::{BeforeMutationFuture, NoBackupProvider},
        local::FileStorageLimits,
        mutation::{MutationActor, StorageNamespace},
        path::RelativeStoragePath,
    };

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lara-coordinator-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn path(value: &str) -> RelativeStoragePath {
        RelativeStoragePath::new(value).unwrap()
    }

    fn namespace() -> StorageNamespace {
        StorageNamespace::new("configuration").unwrap()
    }

    fn actor() -> MutationActor {
        MutationActor::new("42", Some("session-1".into())).unwrap()
    }

    async fn coordinator(
        directory: &TestDirectory,
        guard: Arc<dyn BeforeFileMutation>,
    ) -> FileMutationCoordinator {
        let limits = FileStorageLimits::new(8, 100, 1024).unwrap();
        let storage = LocalFileStorage::open(&directory.0, limits).await.unwrap();
        FileMutationCoordinator::new(storage, guard)
    }

    #[tokio::test]
    async fn creates_overwrites_renames_and_deletes_files_with_events() {
        let directory = TestDirectory::new();
        let coordinator = coordinator(&directory, Arc::new(NoBackupProvider)).await;
        let file = path("server.cfg");

        let create = FileMutationRequest::create(namespace(), actor(), file.clone()).unwrap();
        let created = coordinator
            .execute(
                &create,
                FileMutationPayload::Content(b"hostname one".to_vec()),
                BackupRequirement::Disabled,
            )
            .await
            .unwrap();
        assert_eq!(
            created.kind(),
            crate::shared::file_storage::mutation::FileMutationKind::Create
        );
        assert!(created.previous_revision().is_none());
        assert!(created.current_revision().is_some());

        let overwrite =
            FileMutationRequest::overwrite(namespace(), actor(), file.clone(), None).unwrap();
        let overwritten = coordinator
            .execute(
                &overwrite,
                FileMutationPayload::Content(b"hostname two".to_vec()),
                BackupRequirement::Optional,
            )
            .await
            .unwrap();
        assert!(overwritten.previous_revision().is_some());
        assert_eq!(
            std::fs::read(directory.0.join("server.cfg")).unwrap(),
            b"hostname two"
        );

        let renamed_path = path("renamed.cfg");
        let rename =
            FileMutationRequest::rename(namespace(), actor(), file, renamed_path.clone(), None)
                .unwrap();
        let renamed = coordinator
            .execute(
                &rename,
                FileMutationPayload::None,
                BackupRequirement::Optional,
            )
            .await
            .unwrap();
        assert_eq!(renamed.destination(), Some(&renamed_path));

        let delete = FileMutationRequest::delete(namespace(), actor(), renamed_path, None).unwrap();
        let deleted = coordinator
            .execute(
                &delete,
                FileMutationPayload::None,
                BackupRequirement::Optional,
            )
            .await
            .unwrap();
        assert!(deleted.current_revision().is_none());
        assert!(!directory.0.join("renamed.cfg").exists());
    }

    #[tokio::test]
    async fn required_backup_failure_leaves_the_file_unchanged() {
        let directory = TestDirectory::new();
        std::fs::write(directory.0.join("server.cfg"), b"original").unwrap();
        let coordinator = coordinator(&directory, Arc::new(NoBackupProvider)).await;
        let request =
            FileMutationRequest::overwrite(namespace(), actor(), path("server.cfg"), None).unwrap();

        let result = coordinator
            .execute(
                &request,
                FileMutationPayload::Content(b"changed".to_vec()),
                BackupRequirement::Required,
            )
            .await;

        assert!(matches!(
            result,
            Err(FileMutationCoordinatorError::Guard(
                BeforeFileMutationError::RequiredBackupUnavailable
            ))
        ));
        assert_eq!(
            std::fs::read(directory.0.join("server.cfg")).unwrap(),
            b"original"
        );
    }

    struct MutatingGuard {
        absolute_path: std::path::PathBuf,
    }

    impl BeforeFileMutation for MutatingGuard {
        fn prepare<'a>(
            &'a self,
            request: &'a FileMutationRequest,
            current_file: Option<&'a FileSnapshot>,
            requirement: BackupRequirement,
        ) -> BeforeMutationFuture<'a> {
            Box::pin(async move {
                let permit = MutationPermit::new(request, current_file, None, requirement)?;
                tokio::fs::write(&self.absolute_path, b"raced")
                    .await
                    .unwrap();
                Ok(permit)
            })
        }
    }

    #[tokio::test]
    async fn detects_a_change_between_prepare_and_apply() {
        let directory = TestDirectory::new();
        let absolute_path = directory.0.join("server.cfg");
        std::fs::write(&absolute_path, b"original-longer").unwrap();
        let coordinator = coordinator(&directory, Arc::new(MutatingGuard { absolute_path })).await;
        let request =
            FileMutationRequest::delete(namespace(), actor(), path("server.cfg"), None).unwrap();

        assert!(matches!(
            coordinator
                .execute(
                    &request,
                    FileMutationPayload::None,
                    BackupRequirement::Optional
                )
                .await,
            Err(FileMutationCoordinatorError::ConcurrentModification)
        ));
        assert_eq!(
            std::fs::read(directory.0.join("server.cfg")).unwrap(),
            b"raced"
        );
    }

    #[tokio::test]
    async fn validates_payload_and_size_before_invoking_the_guard() {
        let directory = TestDirectory::new();
        let coordinator = coordinator(&directory, Arc::new(NoBackupProvider)).await;
        let create = FileMutationRequest::create(namespace(), actor(), path("server.cfg")).unwrap();

        assert!(matches!(
            coordinator
                .execute(
                    &create,
                    FileMutationPayload::None,
                    BackupRequirement::Disabled
                )
                .await,
            Err(FileMutationCoordinatorError::PayloadMismatch)
        ));
        assert!(matches!(
            coordinator
                .execute(
                    &create,
                    FileMutationPayload::Content(vec![0; 1025]),
                    BackupRequirement::Disabled,
                )
                .await,
            Err(FileMutationCoordinatorError::ContentTooLarge { maximum_size: 1024 })
        ));
    }
}
