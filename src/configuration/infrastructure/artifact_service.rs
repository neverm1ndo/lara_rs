use std::sync::Arc;

use crate::{
    configuration::{
        application::{
            artifact_service::{
                ConfigurationArtifactContent, ConfigurationArtifactMetadata,
                ConfigurationArtifactService,
            },
            instance_text::{
                ConfigurationEntityTag, ConfigurationResourceKind, InstanceConfigurationError,
                InstanceConfigurationFuture, InstanceConfigurationMutation,
                InstanceConfigurationRequest,
            },
        },
        domain::{ConfigurationAccessLevel, artifact_policy::ConfigurationArtifactPolicy},
        infrastructure::instance_text::{LocalInstanceConfigurationTextService, map_storage_error},
    },
    shared::file_storage::{
        coordinator::FileMutationPayload,
        guard::{BackupRequirement, BeforeFileMutation},
        mutation::{FileMutationRequest, StorageNamespace},
        path::RelativeStoragePath,
    },
};

#[derive(Clone)]
pub struct LocalConfigurationArtifactService {
    mutations: LocalInstanceConfigurationTextService,
    namespace: StorageNamespace,
}

impl LocalConfigurationArtifactService {
    pub fn new(before_mutation: Arc<dyn BeforeFileMutation>) -> Self {
        Self {
            mutations: LocalInstanceConfigurationTextService::new(before_mutation),
            namespace: StorageNamespace::new("configuration")
                .expect("configuration is a valid namespace"),
        }
    }

    fn ensure_allowed(
        context: &InstanceConfigurationRequest,
        path: &RelativeStoragePath,
    ) -> Result<RelativeStoragePath, InstanceConfigurationError> {
        if context.access().level() != ConfigurationAccessLevel::Developer {
            return Err(InstanceConfigurationError::Forbidden);
        }
        let server_path = context.access().server_path(path);
        if !ConfigurationArtifactPolicy::permits(
            &server_path,
            context.target().artifact_paths(),
            context.target().policy(),
        ) {
            return Err(InstanceConfigurationError::NotFound);
        }
        Ok(server_path)
    }
}

impl ConfigurationArtifactService for LocalConfigurationArtifactService {
    fn metadata<'a>(
        &'a self,
        context: InstanceConfigurationRequest,
        path: RelativeStoragePath,
    ) -> InstanceConfigurationFuture<'a, ConfigurationArtifactMetadata> {
        Box::pin(async move {
            let path = Self::ensure_allowed(&context, &path)?;
            LocalInstanceConfigurationTextService::ensure_non_executable(&context, &path).await?;
            let revision = context
                .target()
                .storage()
                .file_revision(&path)
                .await
                .map_err(map_storage_error)?;
            let etag = ConfigurationEntityTag::from_revision(&revision)
                .ok_or(InstanceConfigurationError::ContentTooLarge)?;
            Ok(ConfigurationArtifactMetadata {
                content_length: revision.size(),
                etag,
            })
        })
    }

    fn replace<'a>(
        &'a self,
        context: InstanceConfigurationRequest,
        path: RelativeStoragePath,
        content: ConfigurationArtifactContent,
        expected: ConfigurationEntityTag,
    ) -> InstanceConfigurationFuture<'a, InstanceConfigurationMutation> {
        Box::pin(async move {
            let path = Self::ensure_allowed(&context, &path)?;
            LocalInstanceConfigurationTextService::ensure_non_executable(&context, &path).await?;
            let bytes = content.into_bytes();
            if bytes.len() as u64 > context.target().storage().limits().max_stream_size_bytes {
                return Err(InstanceConfigurationError::ContentTooLarge);
            }
            let revision =
                LocalInstanceConfigurationTextService::current_revision(&context, &path, &expected)
                    .await?;
            let request = FileMutationRequest::overwrite(
                self.namespace.clone(),
                context.actor().clone(),
                path,
                Some(revision),
            )
            .map_err(|_| InstanceConfigurationError::Unavailable)?;
            let mut result = self
                .mutations
                .execute(
                    &context,
                    request,
                    FileMutationPayload::Content(bytes),
                    LocalInstanceConfigurationTextService::destructive_backup(
                        &context,
                        BackupRequirement::Required,
                    ),
                )
                .await?;
            result.resource_kind = ConfigurationResourceKind::Artifact;
            Ok(result)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use encoding_rs::WINDOWS_1251;
    use uuid::Uuid;

    use super::*;
    use crate::{
        configuration::{
            application::target::{
                ConfigurationAccessScope, ConfigurationTarget, ConfigurationTargetError,
                ConfigurationTargetResolver,
            },
            domain::{BinaryExtension, ConfigurationFilePolicy},
        },
        shared::{
            file_storage::{
                guard::NoBackupProvider,
                local::{FileStorageLimits, LocalFileStorage},
                mutation::MutationActor,
            },
            user_role::UserRole,
        },
    };

    struct TestRoots(PathBuf);

    impl TestRoots {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("lara-artifacts-{}", Uuid::new_v4()));
            for name in ["primary", "auxiliary"] {
                std::fs::create_dir_all(root.join(name).join("gamemodes")).unwrap();
            }
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

    fn path(value: &str) -> RelativeStoragePath {
        RelativeStoragePath::new(value).unwrap()
    }

    async fn resolver(roots: &TestRoots) -> StaticResolver {
        let mut targets = BTreeMap::new();
        for (name, scope) in [
            (
                "primary",
                ConfigurationAccessScope::Primary {
                    configurator_directory: path("gamemodes"),
                },
            ),
            ("auxiliary", ConfigurationAccessScope::Auxiliary),
        ] {
            let storage = LocalFileStorage::open(
                roots.path(name),
                FileStorageLimits::new(8, 100, 4).unwrap(),
            )
            .await
            .unwrap();
            let policy = ConfigurationFilePolicy::new(
                [
                    BinaryExtension::new("amx").unwrap(),
                    BinaryExtension::new("so").unwrap(),
                ],
                [],
                [path("logs")],
            )
            .unwrap();
            let target = ConfigurationTarget::new(
                name.to_owned(),
                storage,
                policy,
                WINDOWS_1251,
                vec![
                    path("gamemodes/test.amx"),
                    path("gamemodes/missing.amx"),
                    path("plugins/native.so"),
                ],
                scope,
            );
            targets.insert(name.to_owned(), Arc::new(target));
        }
        StaticResolver(targets)
    }

    fn context(
        resolver: &StaticResolver,
        name: &str,
        role: UserRole,
    ) -> Result<InstanceConfigurationRequest, InstanceConfigurationError> {
        InstanceConfigurationRequest::authorize(
            resolver,
            name,
            role,
            &[],
            MutationActor::new("42", None).unwrap(),
        )
    }

    #[tokio::test]
    async fn replaces_only_existing_allowlisted_binary_without_transcoding_or_backup() {
        let roots = TestRoots::new();
        let artifact = roots.path("auxiliary/gamemodes/test.amx");
        let initial = [0xff, 0x98, 0x00];
        tokio::fs::write(&artifact, initial).await.unwrap();
        let resolver = resolver(&roots).await;
        let developer = context(&resolver, "auxiliary", UserRole::Developer).unwrap();
        let service = LocalConfigurationArtifactService::new(Arc::new(NoBackupProvider));

        let before = service
            .metadata(developer.clone(), path("gamemodes/test.amx"))
            .await
            .unwrap();
        assert_eq!(before.content_length, 3);
        let old_tag = before.etag;
        let replacement = vec![0x98, 0xff, 0x01];
        let changed = service
            .replace(
                developer.clone(),
                path("gamemodes/test.amx"),
                ConfigurationArtifactContent::new(replacement.clone()),
                old_tag.clone(),
            )
            .await
            .unwrap();
        assert_eq!(changed.instance_id, "auxiliary");
        assert_eq!(changed.resource_kind, ConfigurationResourceKind::Artifact);
        assert!(changed.event.backup_receipt().is_none());
        assert_ne!(changed.etag.as_ref().unwrap(), &old_tag);
        assert_eq!(tokio::fs::read(&artifact).await.unwrap(), replacement);
        assert_eq!(
            std::fs::read_dir(roots.path("auxiliary/gamemodes"))
                .unwrap()
                .count(),
            1
        );

        assert!(matches!(
            service
                .replace(
                    developer,
                    path("gamemodes/test.amx"),
                    ConfigurationArtifactContent::new(vec![1, 2]),
                    old_tag,
                )
                .await,
            Err(InstanceConfigurationError::PreconditionFailed)
        ));
    }

    #[tokio::test]
    async fn denies_missing_unlisted_protected_oversized_and_non_developer_targets() {
        let roots = TestRoots::new();
        tokio::fs::write(roots.path("auxiliary/gamemodes/test.amx"), [1, 2, 3])
            .await
            .unwrap();
        tokio::fs::write(roots.path("primary/gamemodes/test.amx"), [1, 2, 3])
            .await
            .unwrap();
        let resolver = resolver(&roots).await;
        let service = LocalConfigurationArtifactService::new(Arc::new(NoBackupProvider));
        let auxiliary = context(&resolver, "auxiliary", UserRole::Developer).unwrap();
        let original = service
            .metadata(auxiliary.clone(), path("gamemodes/test.amx"))
            .await
            .unwrap()
            .etag;

        for denied in [
            "gamemodes/other.amx",
            "gamemodes/TEST.amx",
            "plugins/native.so",
            ".env",
            "omp-server",
        ] {
            assert!(matches!(
                service.metadata(auxiliary.clone(), path(denied)).await,
                Err(InstanceConfigurationError::NotFound)
            ));
        }
        assert!(matches!(
            service
                .metadata(auxiliary.clone(), path("gamemodes/missing.amx"))
                .await,
            Err(InstanceConfigurationError::NotFound)
        ));
        assert!(matches!(
            service
                .replace(
                    auxiliary.clone(),
                    path("gamemodes/missing.amx"),
                    ConfigurationArtifactContent::new(vec![1]),
                    original.clone(),
                )
                .await,
            Err(InstanceConfigurationError::NotFound)
        ));
        tokio::fs::write(roots.path("auxiliary/gamemodes/missing.amx"), vec![7; 5])
            .await
            .unwrap();
        assert!(matches!(
            service
                .metadata(auxiliary.clone(), path("gamemodes/missing.amx"))
                .await,
            Err(InstanceConfigurationError::ContentTooLarge)
        ));
        assert!(matches!(
            service
                .replace(
                    auxiliary.clone(),
                    path("gamemodes/test.amx"),
                    ConfigurationArtifactContent::new(vec![1; 5]),
                    original,
                )
                .await,
            Err(InstanceConfigurationError::ContentTooLarge)
        ));
        assert!(matches!(
            context(&resolver, "auxiliary", UserRole::Configurator),
            Err(InstanceConfigurationError::NotFound)
        ));
        let configurator = context(&resolver, "primary", UserRole::Configurator).unwrap();
        assert!(matches!(
            service.metadata(configurator, path("test.amx")).await,
            Err(InstanceConfigurationError::Forbidden)
        ));

        let primary = context(&resolver, "primary", UserRole::Developer).unwrap();
        let tag = service
            .metadata(primary.clone(), path("gamemodes/test.amx"))
            .await
            .unwrap()
            .etag;
        assert!(matches!(
            service
                .replace(
                    primary,
                    path("gamemodes/test.amx"),
                    ConfigurationArtifactContent::new(vec![4, 5, 6]),
                    tag,
                )
                .await,
            Err(InstanceConfigurationError::Unavailable)
        ));
        assert_eq!(
            tokio::fs::read(roots.path("primary/gamemodes/test.amx"))
                .await
                .unwrap(),
            [1, 2, 3]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn allowlisted_symlink_cannot_read_or_replace_another_instance_artifact() {
        let roots = TestRoots::new();
        let primary_artifact = roots.path("primary/gamemodes/test.amx");
        tokio::fs::write(&primary_artifact, [1, 2, 3])
            .await
            .unwrap();
        std::os::unix::fs::symlink(
            &primary_artifact,
            roots.path("auxiliary/gamemodes/test.amx"),
        )
        .unwrap();
        let resolver = resolver(&roots).await;
        let developer = context(&resolver, "auxiliary", UserRole::Developer).unwrap();
        let service = LocalConfigurationArtifactService::new(Arc::new(NoBackupProvider));
        assert!(matches!(
            service
                .metadata(developer.clone(), path("gamemodes/test.amx"))
                .await,
            Err(InstanceConfigurationError::NotFound)
        ));
        let arbitrary_tag =
            ConfigurationEntityTag::parse(&format!("\"sha256:{}\"", "0".repeat(64))).unwrap();
        assert!(matches!(
            service
                .replace(
                    developer,
                    path("gamemodes/test.amx"),
                    ConfigurationArtifactContent::new(vec![4, 5]),
                    arbitrary_tag,
                )
                .await,
            Err(InstanceConfigurationError::NotFound)
        ));
        assert_eq!(tokio::fs::read(primary_artifact).await.unwrap(), [1, 2, 3]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn allowlisted_file_with_executable_bit_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let roots = TestRoots::new();
        let artifact = roots.path("auxiliary/gamemodes/test.amx");
        tokio::fs::write(&artifact, [1, 2, 3]).await.unwrap();
        std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o750)).unwrap();
        let resolver = resolver(&roots).await;
        let developer = context(&resolver, "auxiliary", UserRole::Developer).unwrap();
        let service = LocalConfigurationArtifactService::new(Arc::new(NoBackupProvider));
        assert!(matches!(
            service
                .metadata(developer.clone(), path("gamemodes/test.amx"))
                .await,
            Err(InstanceConfigurationError::NotFound)
        ));
        let arbitrary_tag =
            ConfigurationEntityTag::parse(&format!("\"sha256:{}\"", "0".repeat(64))).unwrap();
        assert!(matches!(
            service
                .replace(
                    developer,
                    path("gamemodes/test.amx"),
                    ConfigurationArtifactContent::new(vec![4, 5]),
                    arbitrary_tag,
                )
                .await,
            Err(InstanceConfigurationError::NotFound)
        ));
        assert_eq!(tokio::fs::read(artifact).await.unwrap(), [1, 2, 3]);
    }
}
