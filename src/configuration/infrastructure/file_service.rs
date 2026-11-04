use std::{io, sync::Arc};

use crate::{
    configuration::{
        application::file_service::{
            ConfigurationFileContent, ConfigurationFileService, ConfigurationFileServiceError,
            ConfigurationRequestContext, ConfigurationServiceFuture, ConfigurationTextFile,
            ConfigurationTreeEntry, ConfigurationTreeEntryKind,
        },
        domain::{
            ConfigurationFileChanged, ConfigurationFileKind, ConfigurationFilePolicy,
            InvalidConfigurationDomainEvent,
        },
    },
    shared::file_storage::{
        coordinator::{FileMutationCoordinator, FileMutationCoordinatorError, FileMutationPayload},
        guard::{BackupRequirement, BeforeFileMutation},
        local::{LocalFileStorage, LocalFileStorageError, StorageTreeEntry, StorageTreeEntryKind},
        mutation::{FileMutationRequest, InvalidMutationModel, StorageNamespace},
        path::RelativeStoragePath,
    },
};

const CONFIGURATION_NAMESPACE: &str = "configuration";

/// Filesystem adapter for the primary server configuration capability. Each
/// request is narrowed to its authorized root before any storage operation.
#[derive(Clone)]
pub struct LocalConfigurationFileService {
    storage: LocalFileStorage,
    policy: ConfigurationFilePolicy,
    before_mutation: Arc<dyn BeforeFileMutation>,
    namespace: StorageNamespace,
    encoding_label: String,
}

impl LocalConfigurationFileService {
    pub fn new(
        storage: LocalFileStorage,
        policy: ConfigurationFilePolicy,
        before_mutation: Arc<dyn BeforeFileMutation>,
        encoding_label: impl Into<String>,
    ) -> Self {
        Self {
            storage,
            policy,
            before_mutation,
            namespace: StorageNamespace::new(CONFIGURATION_NAMESPACE)
                .expect("configuration namespace is a valid constant"),
            encoding_label: encoding_label.into(),
        }
    }

    async fn scoped(
        &self,
        context: &ConfigurationRequestContext,
    ) -> Result<LocalFileStorage, ConfigurationFileServiceError> {
        self.storage
            .scoped(context.access().storage_root())
            .await
            .map_err(map_storage_error)
    }

    fn ensure_visible(
        &self,
        context: &ConfigurationRequestContext,
        path: &RelativeStoragePath,
    ) -> Result<(), ConfigurationFileServiceError> {
        self.policy
            .ensure_visible(&context.access().server_path(path))
            .map_err(|_| ConfigurationFileServiceError::NotFound)
    }

    fn ensure_text(
        &self,
        context: &ConfigurationRequestContext,
        path: &RelativeStoragePath,
    ) -> Result<(), ConfigurationFileServiceError> {
        self.ensure_visible(context, path)?;
        if self.policy.classify(&context.access().server_path(path))
            == ConfigurationFileKind::Binary
        {
            return Err(ConfigurationFileServiceError::BinaryFile);
        }
        Ok(())
    }

    async fn execute(
        &self,
        context: &ConfigurationRequestContext,
        request: FileMutationRequest,
        payload: FileMutationPayload,
        backup_requirement: BackupRequirement,
    ) -> Result<ConfigurationFileChanged, ConfigurationFileServiceError> {
        let coordinator =
            FileMutationCoordinator::new(self.storage.clone(), self.before_mutation.clone());
        let event = coordinator
            .execute(&request, payload, backup_requirement)
            .await
            .map_err(map_coordinator_error)?;
        ConfigurationFileChanged::from_server_storage(&event, context.access())
            .map_err(map_domain_event_error)
    }
}

impl ConfigurationFileService for LocalConfigurationFileService {
    fn tree<'a>(
        &'a self,
        context: ConfigurationRequestContext,
    ) -> ConfigurationServiceFuture<'a, Vec<ConfigurationTreeEntry>> {
        Box::pin(async move {
            let entries = self
                .scoped(&context)
                .await?
                .tree()
                .await
                .map_err(map_storage_error)?;
            Ok(filter_tree(entries, &context, &self.policy))
        })
    }

    fn open_text<'a>(
        &'a self,
        context: ConfigurationRequestContext,
        path: RelativeStoragePath,
    ) -> ConfigurationServiceFuture<'a, ConfigurationTextFile> {
        Box::pin(async move {
            self.ensure_text(&context, &path)?;
            let file_name = path
                .file_name()
                .ok_or(ConfigurationFileServiceError::NotFound)?
                .to_owned();
            let opened = self
                .scoped(&context)
                .await?
                .open_file(&path)
                .await
                .map_err(map_storage_error)?;
            Ok(ConfigurationTextFile {
                reader: opened.reader,
                content_length: Some(opened.content_length),
                file_name,
                encoding_label: self.encoding_label.clone(),
            })
        })
    }

    fn create<'a>(
        &'a self,
        context: ConfigurationRequestContext,
        path: RelativeStoragePath,
        content: ConfigurationFileContent,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged> {
        Box::pin(async move {
            self.ensure_text(&context, &path)?;
            let path = context.access().server_path(&path);
            let request =
                FileMutationRequest::create(self.namespace.clone(), context.actor().clone(), path)
                    .map_err(map_mutation_model_error)?;
            self.execute(
                &context,
                request,
                FileMutationPayload::Content(content.into_bytes()),
                BackupRequirement::Disabled,
            )
            .await
        })
    }

    fn overwrite<'a>(
        &'a self,
        context: ConfigurationRequestContext,
        path: RelativeStoragePath,
        content: ConfigurationFileContent,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged> {
        Box::pin(async move {
            self.ensure_text(&context, &path)?;
            let path = context.access().server_path(&path);
            let request = FileMutationRequest::overwrite(
                self.namespace.clone(),
                context.actor().clone(),
                path,
                None,
            )
            .map_err(map_mutation_model_error)?;
            self.execute(
                &context,
                request,
                FileMutationPayload::Content(content.into_bytes()),
                BackupRequirement::Required,
            )
            .await
        })
    }

    fn delete<'a>(
        &'a self,
        context: ConfigurationRequestContext,
        path: RelativeStoragePath,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged> {
        Box::pin(async move {
            self.ensure_visible(&context, &path)?;
            let path = context.access().server_path(&path);
            let request = FileMutationRequest::delete(
                self.namespace.clone(),
                context.actor().clone(),
                path,
                None,
            )
            .map_err(map_mutation_model_error)?;
            self.execute(
                &context,
                request,
                FileMutationPayload::None,
                BackupRequirement::Required,
            )
            .await
        })
    }

    fn rename<'a>(
        &'a self,
        context: ConfigurationRequestContext,
        source: RelativeStoragePath,
        destination: RelativeStoragePath,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged> {
        Box::pin(async move {
            self.ensure_visible(&context, &source)?;
            self.ensure_visible(&context, &destination)?;
            let source = context.access().server_path(&source);
            let destination = context.access().server_path(&destination);
            let request = FileMutationRequest::rename(
                self.namespace.clone(),
                context.actor().clone(),
                source,
                destination,
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

fn filter_tree(
    entries: Vec<StorageTreeEntry>,
    context: &ConfigurationRequestContext,
    policy: &ConfigurationFilePolicy,
) -> Vec<ConfigurationTreeEntry> {
    entries
        .into_iter()
        .filter_map(|entry| filter_tree_entry(entry, context, policy))
        .collect()
}

fn filter_tree_entry(
    entry: StorageTreeEntry,
    context: &ConfigurationRequestContext,
    policy: &ConfigurationFilePolicy,
) -> Option<ConfigurationTreeEntry> {
    let server_path = context.access().server_path(entry.path());
    if policy.is_ignored(&server_path) {
        return None;
    }
    let kind = match entry.kind() {
        StorageTreeEntryKind::Directory => ConfigurationTreeEntryKind::Directory,
        StorageTreeEntryKind::File => policy.classify(&server_path).into(),
    };
    let children = filter_tree(entry.children().to_vec(), context, policy);
    Some(ConfigurationTreeEntry {
        path: entry.path().clone(),
        name: entry.name().to_owned(),
        kind,
        size: entry.size(),
        modified_at: entry.modified_at(),
        children,
    })
}

fn map_storage_error(error: LocalFileStorageError) -> ConfigurationFileServiceError {
    match error {
        LocalFileStorageError::Io(error) if error.kind() == io::ErrorKind::NotFound => {
            ConfigurationFileServiceError::NotFound
        }
        LocalFileStorageError::AlreadyExists => ConfigurationFileServiceError::AlreadyExists,
        LocalFileStorageError::ContentTooLarge { .. } => {
            ConfigurationFileServiceError::ContentTooLarge
        }
        LocalFileStorageError::NotFile | LocalFileStorageError::RootFile => {
            ConfigurationFileServiceError::NotFound
        }
        _ => ConfigurationFileServiceError::Unavailable,
    }
}

fn map_coordinator_error(error: FileMutationCoordinatorError) -> ConfigurationFileServiceError {
    match error {
        FileMutationCoordinatorError::ConcurrentModification => {
            ConfigurationFileServiceError::Conflict
        }
        FileMutationCoordinatorError::ContentTooLarge { .. } => {
            ConfigurationFileServiceError::ContentTooLarge
        }
        FileMutationCoordinatorError::Storage(error) => map_storage_error(error),
        FileMutationCoordinatorError::PayloadMismatch
        | FileMutationCoordinatorError::Guard(_)
        | FileMutationCoordinatorError::InvalidPermit(_) => {
            ConfigurationFileServiceError::Unavailable
        }
    }
}

fn map_mutation_model_error(error: InvalidMutationModel) -> ConfigurationFileServiceError {
    match error {
        InvalidMutationModel::RenameToSelf => ConfigurationFileServiceError::Conflict,
        _ => ConfigurationFileServiceError::Unavailable,
    }
}

fn map_domain_event_error(
    _error: InvalidConfigurationDomainEvent,
) -> ConfigurationFileServiceError {
    ConfigurationFileServiceError::Unavailable
}
