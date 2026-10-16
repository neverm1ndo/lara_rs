use std::{io, sync::Arc};

use crate::{
    maps::{
        application::file_service::{
            MapUploadBatch, MapsFileService, MapsFileServiceError, MapsRequestContext,
            MapsServiceFuture, MapsTreeEntry, MapsTreeEntryKind, OpenedMapFile,
        },
        domain::{InvalidMapsDomainEvent, MAPS_STORAGE_NAMESPACE, MapFileChanged, MapFilePolicy},
    },
    shared::file_storage::{
        coordinator::{FileMutationCoordinator, FileMutationCoordinatorError, FileMutationPayload},
        guard::{BackupRequirement, BeforeFileMutation},
        local::{LocalFileStorage, LocalFileStorageError, StorageTreeEntry, StorageTreeEntryKind},
        mutation::{FileMutationRequest, InvalidMutationModel, StorageNamespace},
    },
};

/// Filesystem-backed maps application service. Both authorized roles receive
/// the same storage capability, already rooted at the configured maps folder.
#[derive(Clone)]
pub struct LocalMapsFileService {
    storage: LocalFileStorage,
    coordinator: FileMutationCoordinator,
    namespace: StorageNamespace,
    destructive_backup_requirement: BackupRequirement,
}

impl LocalMapsFileService {
    pub fn new(storage: LocalFileStorage, before_mutation: Arc<dyn BeforeFileMutation>) -> Self {
        Self::with_backup_requirement(storage, before_mutation, BackupRequirement::Optional)
    }

    /// Production constructor used once the backups provider is available.
    /// Overwrite and delete fail closed if preserving the current map fails.
    pub fn with_required_backups(
        storage: LocalFileStorage,
        before_mutation: Arc<dyn BeforeFileMutation>,
    ) -> Self {
        Self::with_backup_requirement(storage, before_mutation, BackupRequirement::Required)
    }

    fn with_backup_requirement(
        storage: LocalFileStorage,
        before_mutation: Arc<dyn BeforeFileMutation>,
        destructive_backup_requirement: BackupRequirement,
    ) -> Self {
        Self {
            coordinator: FileMutationCoordinator::new(storage.clone(), before_mutation),
            storage,
            namespace: StorageNamespace::new(MAPS_STORAGE_NAMESPACE)
                .expect("maps storage namespace is a valid constant"),
            destructive_backup_requirement,
        }
    }

    async fn execute(
        &self,
        context: &MapsRequestContext,
        request: FileMutationRequest,
        payload: FileMutationPayload,
        backup_requirement: BackupRequirement,
    ) -> Result<MapFileChanged, MapsFileServiceError> {
        let event = self
            .coordinator
            .execute(&request, payload, backup_requirement)
            .await
            .map_err(map_coordinator_error)?;

        MapFileChanged::from_storage(&event, context.access()).map_err(map_domain_event_error)
    }
}

impl MapsFileService for LocalMapsFileService {
    fn tree<'a>(
        &'a self,
        _context: MapsRequestContext,
    ) -> MapsServiceFuture<'a, Vec<MapsTreeEntry>> {
        Box::pin(async move {
            let entries = self.storage.tree().await.map_err(map_storage_error)?;
            Ok(filter_tree(entries))
        })
    }

    fn open<'a>(
        &'a self,
        _context: MapsRequestContext,
        path: crate::maps::domain::MapFilePath,
    ) -> MapsServiceFuture<'a, OpenedMapFile> {
        Box::pin(async move {
            let file_name = path.file_name().to_owned();
            let opened = self
                .storage
                .open_file(path.as_storage_path())
                .await
                .map_err(map_storage_error)?;

            Ok(OpenedMapFile {
                reader: opened.reader,
                content_length: opened.content_length,
                file_name,
            })
        })
    }

    fn create_many<'a>(
        &'a self,
        context: MapsRequestContext,
        batch: MapUploadBatch,
    ) -> MapsServiceFuture<'a, Vec<MapFileChanged>> {
        Box::pin(async move {
            let mut events = Vec::with_capacity(batch.len());
            for upload in batch.into_uploads() {
                let (path, content) = upload.into_parts();
                let request = FileMutationRequest::create(
                    self.namespace.clone(),
                    context.actor().clone(),
                    path.into_storage_path(),
                )
                .map_err(map_mutation_model_error)?;
                events.push(
                    self.execute(
                        &context,
                        request,
                        FileMutationPayload::Content(content),
                        BackupRequirement::Disabled,
                    )
                    .await?,
                );
            }
            Ok(events)
        })
    }

    fn overwrite_many<'a>(
        &'a self,
        context: MapsRequestContext,
        batch: MapUploadBatch,
    ) -> MapsServiceFuture<'a, Vec<MapFileChanged>> {
        Box::pin(async move {
            let mut events = Vec::with_capacity(batch.len());
            for upload in batch.into_uploads() {
                let (path, content) = upload.into_parts();
                let request = FileMutationRequest::overwrite(
                    self.namespace.clone(),
                    context.actor().clone(),
                    path.into_storage_path(),
                    None,
                )
                .map_err(map_mutation_model_error)?;
                events.push(
                    self.execute(
                        &context,
                        request,
                        FileMutationPayload::Content(content),
                        self.destructive_backup_requirement,
                    )
                    .await?,
                );
            }
            Ok(events)
        })
    }

    fn delete<'a>(
        &'a self,
        context: MapsRequestContext,
        path: crate::maps::domain::MapFilePath,
    ) -> MapsServiceFuture<'a, MapFileChanged> {
        Box::pin(async move {
            let request = FileMutationRequest::delete(
                self.namespace.clone(),
                context.actor().clone(),
                path.into_storage_path(),
                None,
            )
            .map_err(map_mutation_model_error)?;
            self.execute(
                &context,
                request,
                FileMutationPayload::None,
                self.destructive_backup_requirement,
            )
            .await
        })
    }

    fn rename<'a>(
        &'a self,
        context: MapsRequestContext,
        source: crate::maps::domain::MapFilePath,
        destination: crate::maps::domain::MapFilePath,
    ) -> MapsServiceFuture<'a, MapFileChanged> {
        Box::pin(async move {
            let request = FileMutationRequest::rename(
                self.namespace.clone(),
                context.actor().clone(),
                source.into_storage_path(),
                destination.into_storage_path(),
                None,
            )
            .map_err(map_mutation_model_error)?;
            self.execute(
                &context,
                request,
                FileMutationPayload::None,
                BackupRequirement::Optional,
            )
            .await
        })
    }
}

fn filter_tree(entries: Vec<StorageTreeEntry>) -> Vec<MapsTreeEntry> {
    entries.into_iter().filter_map(filter_tree_entry).collect()
}

fn filter_tree_entry(entry: StorageTreeEntry) -> Option<MapsTreeEntry> {
    let kind = match entry.kind() {
        StorageTreeEntryKind::Directory => MapsTreeEntryKind::Directory,
        StorageTreeEntryKind::File => MapFilePolicy
            .recognize(entry.path())
            .ok()
            .map(|path| MapsTreeEntryKind::from(path.kind()))?,
    };
    let children = filter_tree(entry.children().to_vec());

    if kind == MapsTreeEntryKind::Directory && children.is_empty() {
        return None;
    }

    Some(MapsTreeEntry {
        path: entry.path().clone(),
        name: entry.name().to_owned(),
        kind,
        size: entry.size(),
        modified_at: entry.modified_at(),
        children,
    })
}

fn map_storage_error(error: LocalFileStorageError) -> MapsFileServiceError {
    match error {
        LocalFileStorageError::Io(error) if error.kind() == io::ErrorKind::NotFound => {
            MapsFileServiceError::NotFound
        }
        LocalFileStorageError::AlreadyExists => MapsFileServiceError::AlreadyExists,
        LocalFileStorageError::ContentTooLarge { .. } => MapsFileServiceError::ContentTooLarge,
        LocalFileStorageError::NotFile | LocalFileStorageError::RootFile => {
            MapsFileServiceError::NotFound
        }
        _ => MapsFileServiceError::Unavailable,
    }
}

fn map_coordinator_error(error: FileMutationCoordinatorError) -> MapsFileServiceError {
    match error {
        FileMutationCoordinatorError::ConcurrentModification => MapsFileServiceError::Conflict,
        FileMutationCoordinatorError::ContentTooLarge { .. } => {
            MapsFileServiceError::ContentTooLarge
        }
        FileMutationCoordinatorError::Storage(error) => map_storage_error(error),
        FileMutationCoordinatorError::PayloadMismatch
        | FileMutationCoordinatorError::Guard(_)
        | FileMutationCoordinatorError::InvalidPermit(_) => MapsFileServiceError::Unavailable,
    }
}

fn map_mutation_model_error(error: InvalidMutationModel) -> MapsFileServiceError {
    match error {
        InvalidMutationModel::RenameToSelf => MapsFileServiceError::Conflict,
        _ => MapsFileServiceError::Unavailable,
    }
}

fn map_domain_event_error(_error: InvalidMapsDomainEvent) -> MapsFileServiceError {
    MapsFileServiceError::Unavailable
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use tokio::io::AsyncReadExt;
    use uuid::Uuid;

    use super::*;
    use crate::{
        maps::{
            application::file_service::{MapUpload, MapUploadBatch},
            domain::{MapAccess, MapFileChange, MapFilePath},
        },
        shared::{
            file_storage::{
                guard::NoBackupProvider, local::FileStorageLimits, mutation::MutationActor,
                path::RelativeStoragePath,
            },
            user_role::UserRole,
        },
    };

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lara-maps-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn map_path(value: &str) -> MapFilePath {
        MapFilePath::new(RelativeStoragePath::new(value).unwrap()).unwrap()
    }

    fn context() -> MapsRequestContext {
        MapsRequestContext::new(
            MapAccess::authorize(UserRole::Mapper, &[]).unwrap(),
            MutationActor::new("42", Some("session-1".into())).unwrap(),
        )
    }

    fn batch(items: &[(&str, &[u8])]) -> MapUploadBatch {
        MapUploadBatch::new(
            items
                .iter()
                .map(|(path, content)| MapUpload::new(map_path(path), content.to_vec()))
                .collect(),
        )
        .unwrap()
    }

    async fn service(directory: &TestDirectory) -> LocalMapsFileService {
        let storage = LocalFileStorage::open(
            &directory.0,
            FileStorageLimits::new(8, 100, 1024 * 1024).unwrap(),
        )
        .await
        .unwrap();
        LocalMapsFileService::new(storage, Arc::new(NoBackupProvider))
    }

    async fn service_with_required_backups(directory: &TestDirectory) -> LocalMapsFileService {
        let storage = LocalFileStorage::open(
            &directory.0,
            FileStorageLimits::new(8, 100, 1024 * 1024).unwrap(),
        )
        .await
        .unwrap();
        LocalMapsFileService::with_required_backups(storage, Arc::new(NoBackupProvider))
    }

    #[tokio::test]
    async fn tree_only_contains_map_files_and_their_parent_directories() {
        let directory = TestDirectory::new();
        fs::create_dir_all(directory.0.join("city")).unwrap();
        fs::create_dir_all(directory.0.join("unrelated")).unwrap();
        fs::write(directory.0.join("root.map"), b"root").unwrap();
        fs::write(directory.0.join("city").join("race.map.off"), b"race").unwrap();
        fs::write(directory.0.join("city").join("notes.txt"), b"notes").unwrap();
        fs::write(directory.0.join("unrelated").join("notes.xml"), b"xml").unwrap();

        let tree = service(&directory).await.tree(context()).await.unwrap();

        assert_eq!(tree.len(), 2);
        assert_eq!(tree[0].name, "city");
        assert_eq!(tree[0].kind, MapsTreeEntryKind::Directory);
        assert_eq!(tree[0].children.len(), 1);
        assert_eq!(tree[0].children[0].name, "race.map.off");
        assert_eq!(tree[0].children[0].kind, MapsTreeEntryKind::DisabledMap);
        assert_eq!(tree[1].name, "root.map");
        assert_eq!(tree[1].kind, MapsTreeEntryKind::ActiveMap);
    }

    #[tokio::test]
    async fn streams_the_exact_opaque_file_bytes() {
        let directory = TestDirectory::new();
        let bytes = vec![0, 0xff, 0x98, b'<', b'>'];
        fs::write(directory.0.join("binary.map"), &bytes).unwrap();
        let service = service(&directory).await;

        let mut opened = service
            .open(context(), map_path("binary.map"))
            .await
            .unwrap();
        let mut actual = Vec::new();
        opened.reader.read_to_end(&mut actual).await.unwrap();

        assert_eq!(opened.file_name, "binary.map");
        assert_eq!(opened.content_length, bytes.len() as u64);
        assert_eq!(actual, bytes);
    }

    #[tokio::test]
    async fn creates_and_overwrites_multiple_maps_with_domain_events() {
        let directory = TestDirectory::new();
        fs::create_dir(directory.0.join("city")).unwrap();
        let service = service(&directory).await;

        let created = service
            .create_many(
                context(),
                batch(&[("one.map", b"one"), ("city/two.map.off", b"two")]),
            )
            .await
            .unwrap();
        assert!(matches!(created[0].change(), MapFileChange::Created { .. }));
        assert!(matches!(created[1].change(), MapFileChange::Created { .. }));

        let overwritten = service
            .overwrite_many(
                context(),
                batch(&[("one.map", b"changed"), ("city/two.map.off", b"changed-2")]),
            )
            .await
            .unwrap();
        assert!(
            overwritten
                .iter()
                .all(|event| matches!(event.change(), MapFileChange::Overwritten { .. }))
        );
        assert_eq!(fs::read(directory.0.join("one.map")).unwrap(), b"changed");
        assert_eq!(
            fs::read(directory.0.join("city").join("two.map.off")).unwrap(),
            b"changed-2"
        );
    }

    #[tokio::test]
    async fn required_backup_failure_preserves_existing_map_bytes() {
        let directory = TestDirectory::new();
        fs::write(directory.0.join("race.map"), b"original").unwrap();
        let service = service_with_required_backups(&directory).await;

        let result = service
            .overwrite_many(context(), batch(&[("race.map", b"replacement")]))
            .await;

        assert!(matches!(result, Err(MapsFileServiceError::Unavailable)));
        assert_eq!(fs::read(directory.0.join("race.map")).unwrap(), b"original");
    }

    #[tokio::test]
    async fn renames_between_map_states_and_deletes_the_result() {
        let directory = TestDirectory::new();
        fs::create_dir(directory.0.join("archive")).unwrap();
        fs::write(directory.0.join("race.map"), b"race").unwrap();
        let service = service(&directory).await;

        let renamed = service
            .rename(
                context(),
                map_path("race.map"),
                map_path("archive/race.map.off"),
            )
            .await
            .unwrap();
        assert!(matches!(renamed.change(), MapFileChange::Renamed { .. }));

        let deleted = service
            .delete(context(), map_path("archive/race.map.off"))
            .await
            .unwrap();
        assert!(matches!(deleted.change(), MapFileChange::Deleted { .. }));
        assert!(!directory.0.join("archive").join("race.map.off").exists());
    }

    #[tokio::test]
    async fn maps_expected_storage_failures_to_application_errors() {
        let directory = TestDirectory::new();
        fs::write(directory.0.join("existing.map"), b"one").unwrap();
        let service = service(&directory).await;

        assert!(matches!(
            service.open(context(), map_path("missing.map")).await,
            Err(MapsFileServiceError::NotFound)
        ));
        assert!(matches!(
            service
                .create_many(context(), batch(&[("existing.map", b"two")]))
                .await,
            Err(MapsFileServiceError::AlreadyExists)
        ));
        assert!(matches!(
            service
                .rename(
                    context(),
                    map_path("existing.map"),
                    map_path("existing.map")
                )
                .await,
            Err(MapsFileServiceError::Conflict)
        ));
    }
}
