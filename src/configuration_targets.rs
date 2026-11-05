//! Composition adapter between the instance registry and configuration.
//! No registry infrastructure types cross the configuration application port.

use std::{collections::BTreeMap, error::Error, io, sync::Arc};

use encoding_rs::Encoding;
use thiserror::Error;

use crate::{
    configuration::{
        application::target::{
            ConfigurationAccessScope, ConfigurationTarget, ConfigurationTargetError,
            ConfigurationTargetResolver,
        },
        domain::{BinaryExtension, ConfigurationFilePolicy},
    },
    server_instances::{
        application::registry::InstanceRegistry,
        domain::{InstanceCapability, InstanceKind, ServerInstanceId},
        infrastructure::config_registry::ConfiguredInstanceRegistry,
    },
    shared::{
        config::{AppConfig, model::EffectiveInstanceConfigurationConfig},
        file_storage::{
            local::{FileStorageLimits, LocalFileStorage},
            path::{RelativeStoragePath, StorageFileName},
        },
    },
};

type CatalogSource = Box<dyn Error + Send + Sync>;

#[derive(Debug, Error)]
pub enum ConfigurationTargetCatalogError {
    #[error("configuration target `{instance}` cannot be initialized: {source}")]
    InvalidTarget {
        instance: String,
        #[source]
        source: CatalogSource,
    },
}

impl ConfigurationTargetCatalogError {
    fn target(instance: &str, source: impl Error + Send + Sync + 'static) -> Self {
        Self::InvalidTarget {
            instance: instance.to_owned(),
            source: Box::new(source),
        }
    }
}

/// Immutable catalog built at startup. Every entry owns a separate canonical
/// filesystem capability with its own limits and file policy.
pub struct ConfigurationTargetCatalog {
    registry: Arc<dyn InstanceRegistry>,
    targets: BTreeMap<ServerInstanceId, Arc<ConfigurationTarget>>,
}

impl ConfigurationTargetCatalog {
    pub async fn open(
        config: &AppConfig,
        registry: Arc<ConfiguredInstanceRegistry>,
    ) -> Result<Self, ConfigurationTargetCatalogError> {
        let mut targets: BTreeMap<ServerInstanceId, Arc<ConfigurationTarget>> = BTreeMap::new();

        for descriptor in registry.list() {
            if !descriptor
                .capabilities()
                .contains(InstanceCapability::Configuration)
            {
                continue;
            }

            let instance_id = descriptor.id();
            let id = instance_id.as_str();
            let configured = registry.configured(instance_id).ok_or_else(|| {
                ConfigurationTargetCatalogError::target(
                    id,
                    io::Error::new(io::ErrorKind::NotFound, "registry storage root is missing"),
                )
            })?;
            let policy_config = match config
                .game_server
                .instances
                .iter()
                .find(|entry| entry.id == id)
            {
                Some(entry) => config
                    .effective_configuration_policy(entry)
                    .map_err(|error| ConfigurationTargetCatalogError::target(id, error))?
                    .ok_or_else(|| {
                        ConfigurationTargetCatalogError::target(
                            id,
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "registry and configuration capability disagree",
                            ),
                        )
                    })?,
                None if config.game_server.instances.is_empty()
                    && descriptor.kind() == InstanceKind::Primary =>
                {
                    config
                        .implicit_primary_configuration_policy()
                        .map_err(|error| ConfigurationTargetCatalogError::target(id, error))?
                }
                None => {
                    return Err(ConfigurationTargetCatalogError::target(
                        id,
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "registry and configuration entries disagree",
                        ),
                    ));
                }
            };
            let target = open_target(
                config,
                id,
                descriptor.kind(),
                configured.storage_root(),
                policy_config,
            )
            .await?;
            if let Some((other_id, _)) = targets.iter().find(|(_, other)| {
                let root = target.storage().canonical_root();
                let other_root = other.storage().canonical_root();
                root.starts_with(other_root) || other_root.starts_with(root)
            }) {
                return Err(ConfigurationTargetCatalogError::target(
                    id,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "canonical storage root overlaps configuration target `{other_id}`"
                        ),
                    ),
                ));
            }
            targets.insert(instance_id.clone(), Arc::new(target));
        }

        let registry_port: Arc<dyn InstanceRegistry> = registry;
        Ok(Self {
            registry: registry_port,
            targets,
        })
    }
}

async fn open_target(
    config: &AppConfig,
    id: &str,
    kind: InstanceKind,
    root: &std::path::Path,
    policy_config: EffectiveInstanceConfigurationConfig,
) -> Result<ConfigurationTarget, ConfigurationTargetCatalogError> {
    let limits = FileStorageLimits::new(
        policy_config.max_tree_depth,
        policy_config.max_tree_entries,
        policy_config.max_file_size_bytes,
    )
    .map_err(|error| ConfigurationTargetCatalogError::target(id, error))?;
    let storage = LocalFileStorage::open(root, limits)
        .await
        .map_err(|error| ConfigurationTargetCatalogError::target(id, error))?;
    let encoding =
        Encoding::for_label(policy_config.fallback_encoding.as_bytes()).ok_or_else(|| {
            ConfigurationTargetCatalogError::target(
                id,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "configuration encoding is not recognized",
                ),
            )
        })?;
    let policy = ConfigurationFilePolicy::new(
        policy_config
            .binary_extensions
            .into_iter()
            .map(BinaryExtension::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| ConfigurationTargetCatalogError::target(id, error))?,
        policy_config
            .binary_file_names
            .iter()
            .map(StorageFileName::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| ConfigurationTargetCatalogError::target(id, error))?,
        policy_config
            .ignored_paths
            .iter()
            .map(|path| RelativeStoragePath::try_from(path.as_path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| ConfigurationTargetCatalogError::target(id, error))?,
    )
    .map_err(|error| ConfigurationTargetCatalogError::target(id, error))?;
    let artifacts = policy_config
        .artifact_paths
        .iter()
        .map(|path| RelativeStoragePath::try_from(path.as_path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ConfigurationTargetCatalogError::target(id, error))?;
    let access_scope = match kind {
        InstanceKind::Primary => ConfigurationAccessScope::Primary {
            configurator_directory: RelativeStoragePath::try_from(
                config.configuration.files.configurator_directory.as_path(),
            )
            .map_err(|error| ConfigurationTargetCatalogError::target(id, error))?,
        },
        InstanceKind::Auxiliary => ConfigurationAccessScope::Auxiliary,
    };
    Ok(ConfigurationTarget::new(
        id.to_owned(),
        storage,
        policy,
        encoding,
        artifacts,
        access_scope,
    ))
}

impl ConfigurationTargetResolver for ConfigurationTargetCatalog {
    fn resolve(
        &self,
        instance_id: &str,
    ) -> Result<Arc<ConfigurationTarget>, ConfigurationTargetError> {
        let id =
            ServerInstanceId::new(instance_id).map_err(|_| ConfigurationTargetError::NotFound)?;
        let descriptor = self
            .registry
            .get(&id)
            .ok_or(ConfigurationTargetError::NotFound)?;
        if !descriptor
            .capabilities()
            .contains(InstanceCapability::Configuration)
        {
            return Err(ConfigurationTargetError::CapabilityUnavailable);
        }
        self.targets
            .get(&id)
            .cloned()
            .ok_or(ConfigurationTargetError::CapabilityUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tokio::io::AsyncReadExt;
    use uuid::Uuid;

    use super::*;
    use crate::configuration::domain::ConfigurationFileKind;

    struct TestRoots(PathBuf);

    impl TestRoots {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("lara-configuration-targets-{}", Uuid::new_v4()));
            std::fs::create_dir(&root).unwrap();
            for name in ["primary", "alpha", "beta", "gamma"] {
                std::fs::create_dir(root.join(name)).unwrap();
            }
            Self(root)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        fn config(&self) -> AppConfig {
            let path = |name| self.path(name).to_string_lossy().replace('\\', "/");
            let overlay = format!(
                r#"
[game_server]
primary_instance = "primary"

[[game_server.instances]]
id = "primary"
display_name = "Primary"
kind = "primary"
environment = "production"
management = "external"
capabilities = ["overview", "lifecycle", "configuration", "maps", "backups", "incidents"]

[[game_server.instances]]
id = "alpha"
display_name = "Alpha"
kind = "auxiliary"
environment = "testing"
management = "systemd"
systemd_unit = "lara-game@alpha.service"
storage_root = "{}"
capabilities = ["overview", "lifecycle", "configuration"]

[game_server.instances.configuration]
fallback_encoding = "utf-8"
binary_extensions = ["amx"]
artifact_paths = ["gamemodes/alpha.amx"]
max_tree_entries = 4

[[game_server.instances]]
id = "beta"
display_name = "Beta"
kind = "auxiliary"
environment = "testing"
management = "systemd"
systemd_unit = "lara-game@beta.service"
storage_root = "{}"
capabilities = ["overview", "lifecycle", "configuration"]

[game_server.instances.configuration]
ignored_paths = ["private"]
max_file_size_bytes = 1024

[[game_server.instances]]
id = "gamma"
display_name = "Gamma"
kind = "auxiliary"
environment = "testing"
management = "external"
storage_root = "{}"
capabilities = ["overview", "lifecycle"]

[game_server.storage]
root = "{}"
"#,
                path("alpha"),
                path("beta"),
                path("gamma"),
                path("primary"),
            );
            let environment = [
                ("LARA_JWT__SECRET".to_owned(), "a".repeat(32)),
                ("LARA_MFA__ENCRYPTION_KEY".to_owned(), "11".repeat(32)),
                (
                    "LARA_MYSQL__URL".to_owned(),
                    "mysql://localhost/lara".into(),
                ),
                (
                    "LARA_MONGODB__URI".to_owned(),
                    "mongodb://localhost:27017".into(),
                ),
            ];
            AppConfig::load_explicit_toml(&overlay, environment).unwrap()
        }
    }

    impl Drop for TestRoots {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    async fn read(target: Arc<ConfigurationTarget>) -> Vec<u8> {
        let path = RelativeStoragePath::new("server.cfg").unwrap();
        let mut opened = target.storage().open_file(&path).await.unwrap();
        let mut bytes = Vec::new();
        opened.reader.read_to_end(&mut bytes).await.unwrap();
        bytes
    }

    #[tokio::test]
    async fn resolves_distinct_targets_in_parallel_without_cross_root_access() {
        let roots = TestRoots::new();
        for name in ["primary", "alpha", "beta"] {
            tokio::fs::write(roots.path(name).join("server.cfg"), name)
                .await
                .unwrap();
        }
        tokio::fs::write(roots.path("beta").join("beta-only.cfg"), b"private")
            .await
            .unwrap();

        let config = roots.config();
        let registry =
            Arc::new(ConfiguredInstanceRegistry::from_config(&config.game_server).unwrap());
        let catalog = ConfigurationTargetCatalog::open(&config, registry)
            .await
            .unwrap();
        let primary = catalog.resolve("primary").unwrap();
        let alpha = catalog.resolve("alpha").unwrap();
        let beta = catalog.resolve("beta").unwrap();

        let (primary_bytes, alpha_bytes, beta_bytes) = tokio::join!(
            read(primary.clone()),
            read(alpha.clone()),
            read(beta.clone())
        );
        assert_eq!(primary_bytes, b"primary");
        assert_eq!(alpha_bytes, b"alpha");
        assert_eq!(beta_bytes, b"beta");
        assert_eq!(alpha.encoding().name(), "UTF-8");
        assert_eq!(alpha.storage().limits().max_tree_entries, 4);
        assert_eq!(beta.storage().limits().max_stream_size_bytes, 1024);
        assert_eq!(
            alpha.artifact_paths(),
            &[RelativeStoragePath::new("gamemodes/alpha.amx").unwrap()]
        );
        assert_eq!(
            alpha
                .policy()
                .classify(&RelativeStoragePath::new("test.amx").unwrap()),
            ConfigurationFileKind::Binary
        );
        assert!(primary.access_scope().requires_backup_preservation());
        assert!(!alpha.access_scope().requires_backup_preservation());

        let beta_only = RelativeStoragePath::new("beta-only.cfg").unwrap();
        assert!(alpha.storage().open_file(&beta_only).await.is_err());
        assert!(RelativeStoragePath::new("../beta/beta-only.cfg").is_err());
        assert!(matches!(
            catalog.resolve("gamma"),
            Err(ConfigurationTargetError::CapabilityUnavailable)
        ));
        assert!(matches!(
            catalog.resolve("missing"),
            Err(ConfigurationTargetError::NotFound)
        ));
    }

    #[tokio::test]
    async fn inaccessible_configured_root_fails_with_instance_diagnostic() {
        let roots = TestRoots::new();
        let config = roots.config();
        std::fs::remove_dir(roots.path("alpha")).unwrap();
        let registry =
            Arc::new(ConfiguredInstanceRegistry::from_config(&config.game_server).unwrap());
        let error = ConfigurationTargetCatalog::open(&config, registry)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("`alpha`"));
    }

    #[tokio::test]
    async fn implicit_primary_uses_legacy_configuration_defaults() {
        let roots = TestRoots::new();
        let mut config = roots.config();
        config.game_server.instances.clear();
        config.game_server.primary_instance = "main".into();
        let registry =
            Arc::new(ConfiguredInstanceRegistry::from_config(&config.game_server).unwrap());
        let catalog = ConfigurationTargetCatalog::open(&config, registry)
            .await
            .unwrap();
        let target = catalog.resolve("main").unwrap();
        assert_eq!(target.encoding().name(), "windows-1251");
        assert!(target.artifact_paths().is_empty());
        assert!(target.access_scope().requires_backup_preservation());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_canonical_root_aliases_hidden_by_parent_symlink() {
        let roots = TestRoots::new();
        std::os::unix::fs::symlink(&roots.0, roots.path("alias")).unwrap();
        let mut config = roots.config();
        config
            .game_server
            .instances
            .iter_mut()
            .find(|entry| entry.id == "alpha")
            .unwrap()
            .storage_root = Some(roots.path("alias/alpha"));
        config
            .game_server
            .instances
            .iter_mut()
            .find(|entry| entry.id == "beta")
            .unwrap()
            .storage_root = Some(roots.path("alpha"));
        let registry =
            Arc::new(ConfiguredInstanceRegistry::from_config(&config.game_server).unwrap());
        let error = ConfigurationTargetCatalog::open(&config, registry)
            .await
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("canonical storage root overlaps")
        );
    }
}
