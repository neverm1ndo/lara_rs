use std::{io, sync::Arc};

use crate::{
    configuration::{
        application::{
            file_service::{
                ConfigurationFileContent, ConfigurationRequestContext, ConfigurationTextFile,
                ConfigurationTreeEntry,
            },
            instance_text::{
                ConfigurationEntityTag, ConfigurationResourceKind, InstanceConfigurationError,
                InstanceConfigurationFuture, InstanceConfigurationMutation,
                InstanceConfigurationRequest, InstanceConfigurationTextFile,
                InstanceConfigurationTextService,
            },
        },
        domain::{ConfigurationFileChanged, ConfigurationFileKind},
        infrastructure::file_service::filter_tree,
    },
    shared::file_storage::{
        coordinator::{FileMutationCoordinator, FileMutationCoordinatorError, FileMutationPayload},
        guard::{
            BackupRequirement, BeforeFileMutation, BeforeFileMutationError, InvalidMutationPermit,
        },
        local::LocalFileStorageError,
        mutation::{FileMutationRequest, FileRevision, StorageNamespace},
        path::RelativeStoragePath,
    },
};

#[derive(Clone)]
pub struct LocalInstanceConfigurationTextService {
    before_mutation: Arc<dyn BeforeFileMutation>,
    namespace: StorageNamespace,
}

impl LocalInstanceConfigurationTextService {
    pub fn new(before_mutation: Arc<dyn BeforeFileMutation>) -> Self {
        Self {
            before_mutation,
            namespace: StorageNamespace::new("configuration")
                .expect("configuration is a valid namespace"),
        }
    }

    fn ensure_visible(
        context: &InstanceConfigurationRequest,
        path: &RelativeStoragePath,
    ) -> Result<(), InstanceConfigurationError> {
        context
            .target()
            .policy()
            .ensure_visible(&context.access().server_path(path))
            .map_err(|_| InstanceConfigurationError::NotFound)
    }

    fn ensure_text(
        context: &InstanceConfigurationRequest,
        path: &RelativeStoragePath,
    ) -> Result<(), InstanceConfigurationError> {
        Self::ensure_visible(context, path)?;
        if protected_text_path(&context.access().server_path(path)) {
            return Err(InstanceConfigurationError::NotFound);
        }
        if context
            .target()
            .policy()
            .classify(&context.access().server_path(path))
            == ConfigurationFileKind::Binary
        {
            return Err(InstanceConfigurationError::BinaryFile);
        }
        Ok(())
    }

    pub(crate) async fn ensure_non_executable(
        context: &InstanceConfigurationRequest,
        path: &RelativeStoragePath,
    ) -> Result<(), InstanceConfigurationError> {
        if context
            .target()
            .storage()
            .is_executable_file(path)
            .await
            .map_err(map_storage_error)?
        {
            return Err(InstanceConfigurationError::NotFound);
        }
        Ok(())
    }

    pub(crate) async fn current_revision(
        context: &InstanceConfigurationRequest,
        path: &RelativeStoragePath,
        expected: &ConfigurationEntityTag,
    ) -> Result<FileRevision, InstanceConfigurationError> {
        let revision = context
            .target()
            .storage()
            .file_revision(path)
            .await
            .map_err(map_storage_error)?;
        if revision.size() > context.target().storage().limits().max_stream_size_bytes {
            return Err(InstanceConfigurationError::ContentTooLarge);
        }
        if !expected.matches(&revision) {
            return Err(InstanceConfigurationError::PreconditionFailed);
        }
        Ok(revision)
    }

    pub(crate) async fn execute(
        &self,
        context: &InstanceConfigurationRequest,
        request: FileMutationRequest,
        payload: FileMutationPayload,
        backup: BackupRequirement,
    ) -> Result<InstanceConfigurationMutation, InstanceConfigurationError> {
        let request = match context.mutation_id() {
            Some(id) => request.with_mutation_id(id),
            None => request,
        };
        let coordinator = FileMutationCoordinator::new(
            context.target().storage().clone(),
            Arc::clone(&self.before_mutation),
        );
        let changed = coordinator
            .execute(&request, payload, backup)
            .await
            .map_err(map_coordinator_error)?;
        let event = ConfigurationFileChanged::from_server_storage(&changed, context.access())
            .map_err(|_| InstanceConfigurationError::Unavailable)?;
        let etag = event
            .current_revision()
            .and_then(ConfigurationEntityTag::from_revision);
        Ok(InstanceConfigurationMutation {
            instance_id: context.target().instance_id().to_owned(),
            resource_kind: ConfigurationResourceKind::TextFile,
            event,
            etag,
        })
    }

    pub(crate) fn destructive_backup(
        context: &InstanceConfigurationRequest,
        primary_requirement: BackupRequirement,
    ) -> BackupRequirement {
        if context
            .target()
            .access_scope()
            .requires_backup_preservation()
        {
            primary_requirement
        } else {
            BackupRequirement::Disabled
        }
    }
}

fn protected_text_path(path: &RelativeStoragePath) -> bool {
    let component_is_protected = |component: &str| {
        let normalized = component.to_ascii_lowercase();
        normalized.starts_with('.')
            || matches!(
                normalized.as_str(),
                "omp-server" | "samp03svr" | "systemd" | "secrets" | "private"
            )
    };
    let protected_component = path.components().any(component_is_protected);
    let protected_extension = path
        .file_name()
        .and_then(|name| name.rsplit_once('.'))
        .is_some_and(|(_, extension)| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "env" | "so" | "dll" | "exe" | "service" | "socket" | "key" | "pem" | "p12" | "pfx"
            )
        });
    protected_component || protected_extension
}

fn hide_protected_tree_entries(
    entries: &mut Vec<ConfigurationTreeEntry>,
    context: &InstanceConfigurationRequest,
) {
    entries.retain_mut(|entry| {
        if protected_text_path(&context.access().server_path(&entry.path)) {
            return false;
        }
        hide_protected_tree_entries(&mut entry.children, context);
        true
    });
}

impl InstanceConfigurationTextService for LocalInstanceConfigurationTextService {
    fn tree<'a>(
        &'a self,
        context: InstanceConfigurationRequest,
    ) -> InstanceConfigurationFuture<'a, Vec<ConfigurationTreeEntry>> {
        Box::pin(async move {
            let scoped = context
                .target()
                .storage()
                .scoped(context.access().storage_root())
                .await
                .map_err(map_storage_error)?;
            let entries = scoped.tree().await.map_err(map_storage_error)?;
            let legacy_context =
                ConfigurationRequestContext::new(context.access().clone(), context.actor().clone());
            let mut tree = filter_tree(entries, &legacy_context, context.target().policy());
            hide_protected_tree_entries(&mut tree, &context);
            Ok(tree)
        })
    }

    fn open_text<'a>(
        &'a self,
        context: InstanceConfigurationRequest,
        path: RelativeStoragePath,
    ) -> InstanceConfigurationFuture<'a, InstanceConfigurationTextFile> {
        Box::pin(async move {
            Self::ensure_text(&context, &path)?;
            Self::ensure_non_executable(&context, &context.access().server_path(&path)).await?;
            let name = path
                .file_name()
                .ok_or(InstanceConfigurationError::NotFound)?
                .to_owned();
            let scoped = context
                .target()
                .storage()
                .scoped(context.access().storage_root())
                .await
                .map_err(map_storage_error)?;
            let opened = scoped.open_file(&path).await.map_err(map_storage_error)?;
            let etag = ConfigurationEntityTag::from_revision(&opened.revision)
                .ok_or(InstanceConfigurationError::Unavailable)?;
            Ok(InstanceConfigurationTextFile {
                file: ConfigurationTextFile {
                    reader: opened.reader,
                    content_length: Some(opened.content_length),
                    file_name: name,
                    encoding_label: context.target().encoding().name().to_ascii_lowercase(),
                },
                etag,
            })
        })
    }

    fn create<'a>(
        &'a self,
        context: InstanceConfigurationRequest,
        path: RelativeStoragePath,
        content: ConfigurationFileContent,
    ) -> InstanceConfigurationFuture<'a, InstanceConfigurationMutation> {
        Box::pin(async move {
            Self::ensure_text(&context, &path)?;
            let content = context.validate_content(content.into_bytes())?;
            let request = FileMutationRequest::create(
                self.namespace.clone(),
                context.actor().clone(),
                context.access().server_path(&path),
            )
            .map_err(|_| InstanceConfigurationError::Unavailable)?;
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
        context: InstanceConfigurationRequest,
        path: RelativeStoragePath,
        content: ConfigurationFileContent,
        expected: ConfigurationEntityTag,
    ) -> InstanceConfigurationFuture<'a, InstanceConfigurationMutation> {
        Box::pin(async move {
            Self::ensure_text(&context, &path)?;
            let content = context.validate_content(content.into_bytes())?;
            let server_path = context.access().server_path(&path);
            Self::ensure_non_executable(&context, &server_path).await?;
            let revision = Self::current_revision(&context, &server_path, &expected).await?;
            let request = FileMutationRequest::overwrite(
                self.namespace.clone(),
                context.actor().clone(),
                server_path,
                Some(revision),
            )
            .map_err(|_| InstanceConfigurationError::Unavailable)?;
            self.execute(
                &context,
                request,
                FileMutationPayload::Content(content.into_bytes()),
                Self::destructive_backup(&context, BackupRequirement::Required),
            )
            .await
        })
    }

    fn delete<'a>(
        &'a self,
        context: InstanceConfigurationRequest,
        path: RelativeStoragePath,
        expected: ConfigurationEntityTag,
    ) -> InstanceConfigurationFuture<'a, InstanceConfigurationMutation> {
        Box::pin(async move {
            Self::ensure_text(&context, &path)?;
            let server_path = context.access().server_path(&path);
            Self::ensure_non_executable(&context, &server_path).await?;
            let revision = Self::current_revision(&context, &server_path, &expected).await?;
            let request = FileMutationRequest::delete(
                self.namespace.clone(),
                context.actor().clone(),
                server_path,
                Some(revision),
            )
            .map_err(|_| InstanceConfigurationError::Unavailable)?;
            self.execute(
                &context,
                request,
                FileMutationPayload::None,
                Self::destructive_backup(&context, BackupRequirement::Required),
            )
            .await
        })
    }

    fn rename<'a>(
        &'a self,
        context: InstanceConfigurationRequest,
        source: RelativeStoragePath,
        destination: RelativeStoragePath,
        expected: ConfigurationEntityTag,
    ) -> InstanceConfigurationFuture<'a, InstanceConfigurationMutation> {
        Box::pin(async move {
            Self::ensure_text(&context, &source)?;
            Self::ensure_text(&context, &destination)?;
            let source = context.access().server_path(&source);
            let destination = context.access().server_path(&destination);
            Self::ensure_non_executable(&context, &source).await?;
            let revision = Self::current_revision(&context, &source, &expected).await?;
            let request = FileMutationRequest::rename(
                self.namespace.clone(),
                context.actor().clone(),
                source,
                destination,
                Some(revision),
            )
            .map_err(|_| InstanceConfigurationError::Conflict)?;
            self.execute(
                &context,
                request,
                FileMutationPayload::None,
                Self::destructive_backup(&context, BackupRequirement::Optional),
            )
            .await
        })
    }
}

pub(crate) fn map_storage_error(error: LocalFileStorageError) -> InstanceConfigurationError {
    match error {
        LocalFileStorageError::Io(error) if error.kind() == io::ErrorKind::NotFound => {
            InstanceConfigurationError::NotFound
        }
        LocalFileStorageError::NotFile
        | LocalFileStorageError::RootFile
        | LocalFileStorageError::LinkOrReparsePoint
        | LocalFileStorageError::OutsideRoot
        | LocalFileStorageError::ExecutableFile => InstanceConfigurationError::NotFound,
        LocalFileStorageError::AlreadyExists => InstanceConfigurationError::AlreadyExists,
        LocalFileStorageError::ContentTooLarge { .. } => {
            InstanceConfigurationError::ContentTooLarge
        }
        LocalFileStorageError::ChangedDuringRead => InstanceConfigurationError::Conflict,
        _ => InstanceConfigurationError::Unavailable,
    }
}

fn map_coordinator_error(error: FileMutationCoordinatorError) -> InstanceConfigurationError {
    match error {
        FileMutationCoordinatorError::ConcurrentModification
        | FileMutationCoordinatorError::InvalidPermit(InvalidMutationPermit::StaleRevision)
        | FileMutationCoordinatorError::Guard(BeforeFileMutationError::InvalidPermit(
            InvalidMutationPermit::StaleRevision,
        )) => InstanceConfigurationError::PreconditionFailed,
        FileMutationCoordinatorError::ContentTooLarge { .. } => {
            InstanceConfigurationError::ContentTooLarge
        }
        FileMutationCoordinatorError::Storage(error) => map_storage_error(error),
        _ => InstanceConfigurationError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use encoding_rs::{UTF_8, WINDOWS_1251};
    use uuid::Uuid;

    use super::*;
    use crate::{
        configuration::{
            application::target::{
                ConfigurationAccessScope, ConfigurationTarget, ConfigurationTargetError,
                ConfigurationTargetResolver,
            },
            domain::ConfigurationFilePolicy,
        },
        shared::file_storage::{
            guard::NoBackupProvider,
            local::{FileStorageLimits, LocalFileStorage},
            mutation::MutationActor,
        },
        shared::user_role::UserRole,
    };

    struct TestRoots(PathBuf);

    impl TestRoots {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("lara-instance-text-{}", Uuid::new_v4()));
            std::fs::create_dir(&root).unwrap();
            std::fs::create_dir(root.join("primary")).unwrap();
            std::fs::create_dir(root.join("auxiliary")).unwrap();
            std::fs::create_dir(root.join("auxiliary-two")).unwrap();
            std::fs::create_dir_all(root.join("primary/scriptfiles/config")).unwrap();
            Self(root)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestRoots {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    struct StaticResolver(BTreeMap<String, Arc<ConfigurationTarget>>);

    impl ConfigurationTargetResolver for StaticResolver {
        fn resolve(&self, id: &str) -> Result<Arc<ConfigurationTarget>, ConfigurationTargetError> {
            self.0
                .get(id)
                .cloned()
                .ok_or(ConfigurationTargetError::NotFound)
        }
    }

    async fn resolver(roots: &TestRoots) -> StaticResolver {
        let mut targets = BTreeMap::new();
        for (id, scope, encoding) in [
            (
                "primary",
                ConfigurationAccessScope::Primary {
                    configurator_directory: RelativeStoragePath::new("scriptfiles/config").unwrap(),
                },
                WINDOWS_1251,
            ),
            ("auxiliary", ConfigurationAccessScope::Auxiliary, UTF_8),
            ("auxiliary-two", ConfigurationAccessScope::Auxiliary, UTF_8),
        ] {
            let storage = LocalFileStorage::open(
                roots.path(id),
                FileStorageLimits::new(8, 100, 1024).unwrap(),
            )
            .await
            .unwrap();
            let policy = ConfigurationFilePolicy::new([], [], []).unwrap();
            targets.insert(
                id.to_owned(),
                Arc::new(ConfigurationTarget::new(
                    id.to_owned(),
                    storage,
                    policy,
                    encoding,
                    vec![],
                    scope,
                )),
            );
        }
        StaticResolver(targets)
    }

    fn context(
        resolver: &StaticResolver,
        id: &str,
        role: UserRole,
    ) -> Result<InstanceConfigurationRequest, InstanceConfigurationError> {
        InstanceConfigurationRequest::authorize(
            resolver,
            id,
            role,
            &[],
            MutationActor::new("42", None).unwrap(),
        )
    }

    fn path(value: &str) -> RelativeStoragePath {
        RelativeStoragePath::new(value).unwrap()
    }

    #[tokio::test]
    async fn concurrent_auxiliary_writes_stay_within_their_own_roots() {
        let roots = TestRoots::new();
        let resolver = resolver(&roots).await;
        let service = LocalInstanceConfigurationTextService::new(Arc::new(NoBackupProvider));
        let first = context(&resolver, "auxiliary", UserRole::Developer).unwrap();
        let second = context(&resolver, "auxiliary-two", UserRole::Developer).unwrap();
        let (first_result, second_result) = tokio::join!(
            service.create(
                first.clone(),
                path("server.cfg"),
                first.validate_content(b"first".to_vec()).unwrap(),
            ),
            service.create(
                second.clone(),
                path("server.cfg"),
                second.validate_content(b"second".to_vec()).unwrap(),
            ),
        );
        assert_eq!(first_result.unwrap().instance_id, "auxiliary");
        assert_eq!(second_result.unwrap().instance_id, "auxiliary-two");
        assert_eq!(
            std::fs::read(roots.path("auxiliary/server.cfg")).unwrap(),
            b"first"
        );
        assert_eq!(
            std::fs::read(roots.path("auxiliary-two/server.cfg")).unwrap(),
            b"second"
        );
        assert!(!roots.path("primary/server.cfg").exists());
    }

    #[tokio::test]
    async fn auxiliary_text_mutations_are_isolated_and_skip_backups() {
        let roots = TestRoots::new();
        let resolver = resolver(&roots).await;
        let service = LocalInstanceConfigurationTextService::new(Arc::new(NoBackupProvider));
        let auxiliary = context(&resolver, "auxiliary", UserRole::Developer).unwrap();
        let first = auxiliary.validate_content(b"first".to_vec()).unwrap();
        let created = service
            .create(auxiliary.clone(), path("server.cfg"), first)
            .await
            .unwrap();
        assert_eq!(created.instance_id, "auxiliary");
        assert_eq!(created.resource_kind, ConfigurationResourceKind::TextFile);
        assert!(created.event.backup_receipt().is_none());
        assert!(roots.path("auxiliary/server.cfg").exists());
        assert!(!roots.path("primary/server.cfg").exists());

        let read = service
            .open_text(auxiliary.clone(), path("server.cfg"))
            .await
            .unwrap();
        let original_tag = read.etag;
        assert_eq!(read.file.encoding_label, "utf-8");
        let stale =
            ConfigurationEntityTag::parse(&format!("\"sha256:{}\"", "0".repeat(64))).unwrap();
        let content = auxiliary.validate_content(b"second".to_vec()).unwrap();
        assert!(matches!(
            service
                .overwrite(
                    auxiliary.clone(),
                    path("server.cfg"),
                    content.clone(),
                    stale
                )
                .await,
            Err(InstanceConfigurationError::PreconditionFailed)
        ));
        let changed = service
            .overwrite(auxiliary.clone(), path("server.cfg"), content, original_tag)
            .await
            .unwrap();
        assert!(changed.event.backup_receipt().is_none());
        assert_eq!(changed.etag.as_ref().unwrap().header_value().len(), 73);
        assert_eq!(
            tokio::fs::read(roots.path("auxiliary/server.cfg"))
                .await
                .unwrap(),
            b"second"
        );
        assert_eq!(
            std::fs::read_dir(roots.path("auxiliary")).unwrap().count(),
            1
        );

        let renamed = service
            .rename(
                auxiliary.clone(),
                path("server.cfg"),
                path("renamed.cfg"),
                changed.etag.unwrap(),
            )
            .await
            .unwrap();
        assert!(roots.path("auxiliary/renamed.cfg").exists());
        let deleted = service
            .delete(
                auxiliary.clone(),
                path("renamed.cfg"),
                renamed.etag.unwrap(),
            )
            .await
            .unwrap();
        assert!(deleted.etag.is_none());
        assert!(!roots.path("auxiliary/renamed.cfg").exists());
    }

    #[tokio::test]
    async fn primary_destructive_mutation_requires_backup_and_role_scope_is_enforced() {
        let roots = TestRoots::new();
        tokio::fs::write(roots.path("primary/server.cfg"), b"original")
            .await
            .unwrap();
        let resolver = resolver(&roots).await;
        let service = LocalInstanceConfigurationTextService::new(Arc::new(NoBackupProvider));
        let primary = context(&resolver, "primary", UserRole::Developer).unwrap();
        let read = service
            .open_text(primary.clone(), path("server.cfg"))
            .await
            .unwrap();
        let replacement = primary.validate_content(b"changed".to_vec()).unwrap();
        assert!(matches!(
            service
                .overwrite(primary, path("server.cfg"), replacement, read.etag)
                .await,
            Err(InstanceConfigurationError::Unavailable)
        ));
        assert_eq!(
            tokio::fs::read(roots.path("primary/server.cfg"))
                .await
                .unwrap(),
            b"original"
        );

        assert!(matches!(
            context(&resolver, "auxiliary", UserRole::Configurator),
            Err(InstanceConfigurationError::NotFound)
        ));
        assert!(matches!(
            context(&resolver, "primary", UserRole::Admin),
            Err(InstanceConfigurationError::Forbidden)
        ));
        let configurator = context(&resolver, "primary", UserRole::Configurator).unwrap();
        assert_eq!(
            configurator.access().storage_root(),
            &path("scriptfiles/config")
        );
        tokio::fs::write(
            roots.path("primary/scriptfiles/config/allowed.cfg"),
            b"allowed",
        )
        .await
        .unwrap();
        assert!(
            service
                .open_text(configurator.clone(), path("allowed.cfg"))
                .await
                .is_ok()
        );
        assert!(matches!(
            service.open_text(configurator, path("server.cfg")).await,
            Err(InstanceConfigurationError::NotFound)
        ));
        assert!(RelativeStoragePath::new("../server.cfg").is_err());
        assert!(matches!(
            context(&resolver, "missing", UserRole::Developer),
            Err(InstanceConfigurationError::NotFound)
        ));
    }

    #[tokio::test]
    async fn two_writes_with_the_same_etag_cannot_both_succeed() {
        let roots = TestRoots::new();
        tokio::fs::write(roots.path("auxiliary/server.cfg"), b"initial")
            .await
            .unwrap();
        let resolver = resolver(&roots).await;
        let service = LocalInstanceConfigurationTextService::new(Arc::new(NoBackupProvider));
        let auxiliary = context(&resolver, "auxiliary", UserRole::Developer).unwrap();
        let etag = service
            .open_text(auxiliary.clone(), path("server.cfg"))
            .await
            .unwrap()
            .etag;
        let left = service.overwrite(
            auxiliary.clone(),
            path("server.cfg"),
            auxiliary.validate_content(b"left".to_vec()).unwrap(),
            etag.clone(),
        );
        let right = service.overwrite(
            auxiliary.clone(),
            path("server.cfg"),
            auxiliary.validate_content(b"right".to_vec()).unwrap(),
            etag,
        );
        let (left, right) = tokio::join!(left, right);
        assert_eq!(left.is_ok() as u8 + right.is_ok() as u8, 1);
        assert!(matches!(
            left.err().or_else(|| right.err()),
            Some(InstanceConfigurationError::PreconditionFailed)
        ));
    }

    #[tokio::test]
    async fn same_length_external_edit_invalidates_content_etag() {
        let roots = TestRoots::new();
        tokio::fs::write(roots.path("auxiliary/server.cfg"), b"alpha")
            .await
            .unwrap();
        let resolver = resolver(&roots).await;
        let service = LocalInstanceConfigurationTextService::new(Arc::new(NoBackupProvider));
        let auxiliary = context(&resolver, "auxiliary", UserRole::Developer).unwrap();
        let old_tag = service
            .open_text(auxiliary.clone(), path("server.cfg"))
            .await
            .unwrap()
            .etag;
        tokio::fs::write(roots.path("auxiliary/server.cfg"), b"bravo")
            .await
            .unwrap();
        let new_tag = service
            .open_text(auxiliary.clone(), path("server.cfg"))
            .await
            .unwrap()
            .etag;
        assert_ne!(old_tag, new_tag);
        assert!(matches!(
            service.delete(auxiliary, path("server.cfg"), old_tag).await,
            Err(InstanceConfigurationError::PreconditionFailed)
        ));
    }

    #[test]
    fn blocks_protected_paths_even_when_binary_classifier_is_empty() {
        for protected in [
            ".env",
            "plugins/native.so",
            "omp-server",
            "systemd/unit.service",
            "private/secret.cfg",
        ] {
            assert!(protected_text_path(&path(protected)), "{protected}");
        }
        assert!(!protected_text_path(&path("scriptfiles/config/server.cfg")));
    }

    #[tokio::test]
    async fn protected_files_are_hidden_from_tree_and_direct_access() {
        let roots = TestRoots::new();
        tokio::fs::write(roots.path("auxiliary/.env"), b"secret")
            .await
            .unwrap();
        tokio::fs::write(roots.path("auxiliary/server.cfg"), b"visible")
            .await
            .unwrap();
        let resolver = resolver(&roots).await;
        let service = LocalInstanceConfigurationTextService::new(Arc::new(NoBackupProvider));
        let auxiliary = context(&resolver, "auxiliary", UserRole::Developer).unwrap();
        let tree = service.tree(auxiliary.clone()).await.unwrap();
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].name, "server.cfg");
        assert!(matches!(
            service.open_text(auxiliary, path(".env")).await,
            Err(InstanceConfigurationError::NotFound)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn executable_text_file_is_not_accessible_or_mutable() {
        use std::os::unix::fs::PermissionsExt;

        let roots = TestRoots::new();
        let file = roots.path("auxiliary/script.pwn");
        tokio::fs::write(&file, b"script").await.unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o750)).unwrap();
        let resolver = resolver(&roots).await;
        let service = LocalInstanceConfigurationTextService::new(Arc::new(NoBackupProvider));
        let developer = context(&resolver, "auxiliary", UserRole::Developer).unwrap();
        assert!(matches!(
            service
                .open_text(developer.clone(), path("script.pwn"))
                .await,
            Err(InstanceConfigurationError::NotFound)
        ));
        let arbitrary_tag =
            ConfigurationEntityTag::parse(&format!("\"sha256:{}\"", "0".repeat(64))).unwrap();
        assert!(matches!(
            service
                .delete(developer, path("script.pwn"), arbitrary_tag)
                .await,
            Err(InstanceConfigurationError::NotFound)
        ));
        assert_eq!(tokio::fs::read(file).await.unwrap(), b"script");
    }
}
