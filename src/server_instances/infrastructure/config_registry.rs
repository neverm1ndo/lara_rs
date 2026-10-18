use std::{
    collections::{BTreeMap, HashSet},
    path::{Component, Path, PathBuf},
};

use thiserror::Error;

use crate::{
    server_instances::{
        application::registry::InstanceRegistry,
        domain::{
            InstanceCapabilities, InstanceCapability, InstanceEnvironment, InstanceKind,
            InstanceObservability, InstanceReadiness, InvalidServerInstance, ServerInstance,
            ServerInstanceId,
        },
    },
    shared::config::model::{
        GameServerConfig, InstanceCapabilityConfig, InstanceEnvironmentConfig, InstanceKindConfig,
        InstanceReadinessConfig, ServerInstanceConfig,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdUnitName(String);

impl SystemdUnitName {
    fn new(value: impl Into<String>) -> Result<Self, InstanceRegistryError> {
        let value = value.into();
        let valid = value.ends_with(".service")
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@' | b':')
            });
        if !valid {
            return Err(InstanceRegistryError::InvalidSystemdUnit(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct ConfiguredServerInstance {
    descriptor: ServerInstance,
    systemd_unit: SystemdUnitName,
    storage_root: PathBuf,
}

impl ConfiguredServerInstance {
    pub fn descriptor(&self) -> &ServerInstance {
        &self.descriptor
    }

    pub fn systemd_unit(&self) -> &SystemdUnitName {
        &self.systemd_unit
    }

    pub fn storage_root(&self) -> &Path {
        &self.storage_root
    }
}

#[derive(Debug)]
pub struct ConfiguredInstanceRegistry {
    primary_id: ServerInstanceId,
    instances: BTreeMap<ServerInstanceId, ConfiguredServerInstance>,
}

impl ConfiguredInstanceRegistry {
    pub fn from_config(config: &GameServerConfig) -> Result<Self, InstanceRegistryError> {
        let registrations = if config.instances.is_empty() {
            vec![legacy_primary(config)]
        } else {
            config.instances.clone()
        };
        let primary_id = ServerInstanceId::new(config.primary_instance.clone())?;
        let mut instances = BTreeMap::new();
        let mut units = HashSet::new();
        let mut roots: Vec<(ServerInstanceId, PathBuf)> = Vec::new();

        for registration in registrations {
            let configured = configured_instance(registration, config)?;
            let id = configured.descriptor.id().clone();
            if instances.contains_key(&id) {
                return Err(InstanceRegistryError::DuplicateIdentifier(id));
            }
            if !units.insert(configured.systemd_unit.0.clone()) {
                return Err(InstanceRegistryError::DuplicateSystemdUnit(
                    configured.systemd_unit.0,
                ));
            }
            let normalized_root = normalize_path(&configured.storage_root)?;
            if let Some((other_id, _)) = roots
                .iter()
                .find(|(_, other)| paths_overlap(other.as_path(), normalized_root.as_path()))
            {
                return Err(InstanceRegistryError::OverlappingStorageRoots {
                    first: other_id.clone(),
                    second: id,
                });
            }
            roots.push((id.clone(), normalized_root));
            instances.insert(id, configured);
        }

        let primary = instances
            .get(&primary_id)
            .ok_or_else(|| InstanceRegistryError::PrimaryNotFound(primary_id.clone()))?;
        if primary.descriptor.kind() != InstanceKind::Primary {
            return Err(InstanceRegistryError::PrimaryKind(primary_id));
        }
        let primary_count = instances
            .values()
            .filter(|instance| instance.descriptor.kind() == InstanceKind::Primary)
            .count();
        if primary_count != 1 {
            return Err(InstanceRegistryError::PrimaryCount(primary_count));
        }

        Ok(Self {
            primary_id,
            instances,
        })
    }

    pub fn configured(&self, id: &ServerInstanceId) -> Option<&ConfiguredServerInstance> {
        self.instances.get(id)
    }
}

impl InstanceRegistry for ConfiguredInstanceRegistry {
    fn primary(&self) -> ServerInstance {
        self.instances[&self.primary_id].descriptor.clone()
    }

    fn get(&self, id: &ServerInstanceId) -> Option<ServerInstance> {
        self.instances
            .get(id)
            .map(|instance| instance.descriptor.clone())
    }

    fn list(&self) -> Vec<ServerInstance> {
        let mut instances: Vec<_> = self
            .instances
            .values()
            .map(|instance| instance.descriptor.clone())
            .collect();
        instances.sort_by(|left, right| {
            left.sort_order()
                .cmp(&right.sort_order())
                .then_with(|| left.id().cmp(right.id()))
        });
        instances
    }
}

fn legacy_primary(config: &GameServerConfig) -> ServerInstanceConfig {
    ServerInstanceConfig {
        id: config.primary_instance.clone(),
        display_name: "Main server".into(),
        kind: InstanceKindConfig::Primary,
        environment: InstanceEnvironmentConfig::Production,
        sort_order: 10,
        systemd_unit: format!("lara-game@{}.service", config.primary_instance),
        storage_root: None,
        capabilities: vec![
            InstanceCapabilityConfig::Overview,
            InstanceCapabilityConfig::Lifecycle,
            InstanceCapabilityConfig::Configuration,
            InstanceCapabilityConfig::Maps,
            InstanceCapabilityConfig::Backups,
            InstanceCapabilityConfig::Incidents,
        ],
        readiness: Some(InstanceReadinessConfig::Uds),
        incident_tracking: true,
    }
}

fn configured_instance(
    registration: ServerInstanceConfig,
    config: &GameServerConfig,
) -> Result<ConfiguredServerInstance, InstanceRegistryError> {
    let id = ServerInstanceId::new(registration.id)?;
    let kind = match registration.kind {
        InstanceKindConfig::Primary => InstanceKind::Primary,
        InstanceKindConfig::Auxiliary => InstanceKind::Auxiliary,
    };
    let environment = match registration.environment {
        InstanceEnvironmentConfig::Production => InstanceEnvironment::Production,
        InstanceEnvironmentConfig::Development => InstanceEnvironment::Development,
        InstanceEnvironmentConfig::Testing => InstanceEnvironment::Testing,
    };
    let readiness = match registration.readiness.unwrap_or(match kind {
        InstanceKind::Primary => InstanceReadinessConfig::Uds,
        InstanceKind::Auxiliary => InstanceReadinessConfig::Process,
    }) {
        InstanceReadinessConfig::Process => InstanceReadiness::Process,
        InstanceReadinessConfig::Uds => InstanceReadiness::Uds,
    };
    let mut unique_capabilities = HashSet::new();
    for capability in &registration.capabilities {
        if !unique_capabilities.insert(*capability) {
            return Err(InstanceRegistryError::DuplicateCapability {
                instance: id,
                capability: format!("{capability:?}").to_ascii_lowercase(),
            });
        }
    }
    let capabilities =
        InstanceCapabilities::new(registration.capabilities.into_iter().map(|capability| {
            match capability {
                InstanceCapabilityConfig::Overview => InstanceCapability::Overview,
                InstanceCapabilityConfig::Lifecycle => InstanceCapability::Lifecycle,
                InstanceCapabilityConfig::Configuration => InstanceCapability::Configuration,
                InstanceCapabilityConfig::Maps => InstanceCapability::Maps,
                InstanceCapabilityConfig::Backups => InstanceCapability::Backups,
                InstanceCapabilityConfig::Incidents => InstanceCapability::Incidents,
            }
        }));
    let storage_root = match (kind, registration.storage_root) {
        (InstanceKind::Primary, None) => config.storage.root.clone(),
        (_, Some(root)) if !root.as_os_str().is_empty() => root,
        (InstanceKind::Auxiliary, None) => {
            return Err(InstanceRegistryError::MissingStorageRoot(id));
        }
        (_, Some(_)) => return Err(InstanceRegistryError::EmptyStorageRoot(id)),
    };
    let descriptor = ServerInstance::new(
        id,
        registration.display_name,
        kind,
        environment,
        registration.sort_order,
        capabilities,
        InstanceObservability::new(readiness, registration.incident_tracking),
    )?;

    Ok(ConfiguredServerInstance {
        descriptor,
        systemd_unit: SystemdUnitName::new(registration.systemd_unit)?,
        storage_root,
    })
}

fn normalize_path(path: &Path) -> Result<PathBuf, InstanceRegistryError> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(InstanceRegistryError::ResolveWorkingDirectory)?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    Ok(normalized)
}

fn paths_overlap(first: &Path, second: &Path) -> bool {
    #[cfg(windows)]
    {
        let first = first.to_string_lossy().to_ascii_lowercase();
        let second = second.to_string_lossy().to_ascii_lowercase();
        let first = Path::new(&first);
        let second = Path::new(&second);
        first.starts_with(second) || second.starts_with(first)
    }
    #[cfg(not(windows))]
    {
        first.starts_with(second) || second.starts_with(first)
    }
}

#[derive(Debug, Error)]
pub enum InstanceRegistryError {
    #[error(transparent)]
    InvalidInstance(#[from] InvalidServerInstance),
    #[error("duplicate server instance identifier `{0}`")]
    DuplicateIdentifier(ServerInstanceId),
    #[error("duplicate systemd unit `{0}`")]
    DuplicateSystemdUnit(String),
    #[error("invalid systemd service unit `{0}`")]
    InvalidSystemdUnit(String),
    #[error("server instance `{instance}` declares capability `{capability}` more than once")]
    DuplicateCapability {
        instance: ServerInstanceId,
        capability: String,
    },
    #[error("configured primary server instance `{0}` was not found")]
    PrimaryNotFound(ServerInstanceId),
    #[error("configured primary server instance `{0}` is not declared as primary")]
    PrimaryKind(ServerInstanceId),
    #[error("server instance registry must contain exactly one primary; found {0}")]
    PrimaryCount(usize),
    #[error("auxiliary server instance `{0}` requires a storage root")]
    MissingStorageRoot(ServerInstanceId),
    #[error("server instance `{0}` has an empty storage root")]
    EmptyStorageRoot(ServerInstanceId),
    #[error("storage roots of server instances `{first}` and `{second}` overlap")]
    OverlappingStorageRoots {
        first: ServerInstanceId,
        second: ServerInstanceId,
    },
    #[error("failed to resolve the process working directory")]
    ResolveWorkingDirectory(#[source] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::config::model::FileStorageConfig;

    fn config(instances: Vec<ServerInstanceConfig>) -> GameServerConfig {
        GameServerConfig {
            primary_instance: "main".into(),
            instances,
            storage: FileStorageConfig {
                root: "/srv/openmp/main".into(),
                max_tree_depth: 32,
                max_tree_entries: 10_000,
                max_stream_size_bytes: 10 * 1024 * 1024,
            },
        }
    }

    fn primary() -> ServerInstanceConfig {
        ServerInstanceConfig {
            id: "main".into(),
            display_name: "Main".into(),
            kind: InstanceKindConfig::Primary,
            environment: InstanceEnvironmentConfig::Production,
            sort_order: 10,
            systemd_unit: "lara-game@main.service".into(),
            storage_root: None,
            capabilities: vec![
                InstanceCapabilityConfig::Overview,
                InstanceCapabilityConfig::Lifecycle,
                InstanceCapabilityConfig::Configuration,
                InstanceCapabilityConfig::Maps,
                InstanceCapabilityConfig::Backups,
                InstanceCapabilityConfig::Incidents,
            ],
            readiness: Some(InstanceReadinessConfig::Uds),
            incident_tracking: true,
        }
    }

    fn auxiliary(id: &str, root: &str) -> ServerInstanceConfig {
        ServerInstanceConfig {
            id: id.into(),
            display_name: id.into(),
            kind: InstanceKindConfig::Auxiliary,
            environment: InstanceEnvironmentConfig::Development,
            sort_order: 20,
            systemd_unit: format!("lara-game@{id}.service"),
            storage_root: Some(root.into()),
            capabilities: vec![
                InstanceCapabilityConfig::Overview,
                InstanceCapabilityConfig::Lifecycle,
                InstanceCapabilityConfig::Configuration,
                InstanceCapabilityConfig::Incidents,
            ],
            readiness: Some(InstanceReadinessConfig::Process),
            incident_tracking: true,
        }
    }

    #[test]
    fn builds_an_ordered_registry_with_one_primary() {
        let registry = ConfiguredInstanceRegistry::from_config(&config(vec![
            primary(),
            auxiliary("dev-dm", "/srv/openmp/dev-dm"),
        ]))
        .unwrap();

        assert_eq!(registry.primary().id().as_str(), "main");
        assert_eq!(registry.list().len(), 2);
        let dev = ServerInstanceId::new("dev-dm").unwrap();
        assert_eq!(
            registry.configured(&dev).unwrap().systemd_unit().as_str(),
            "lara-game@dev-dm.service"
        );
    }

    #[test]
    fn synthesizes_a_legacy_primary_when_the_list_is_absent() {
        let registry = ConfiguredInstanceRegistry::from_config(&config(vec![])).unwrap();

        assert_eq!(registry.primary().id().as_str(), "main");
        assert_eq!(registry.list().len(), 1);
        assert_eq!(
            registry.primary().observability().readiness(),
            InstanceReadiness::Uds
        );
    }

    #[test]
    fn rejects_duplicate_ids_units_and_overlapping_roots() {
        let duplicate_id = ConfiguredInstanceRegistry::from_config(&config(vec![
            primary(),
            auxiliary("main", "/srv/openmp/dev"),
        ]));
        assert!(matches!(
            duplicate_id,
            Err(InstanceRegistryError::DuplicateIdentifier(_))
        ));

        let mut duplicate_unit = auxiliary("dev-dm", "/srv/openmp/dev-dm");
        duplicate_unit.systemd_unit = "lara-game@main.service".into();
        assert!(matches!(
            ConfiguredInstanceRegistry::from_config(&config(vec![primary(), duplicate_unit])),
            Err(InstanceRegistryError::DuplicateSystemdUnit(_))
        ));

        assert!(matches!(
            ConfiguredInstanceRegistry::from_config(&config(vec![
                primary(),
                auxiliary("dev-dm", "/srv/openmp/main/dev-dm"),
            ])),
            Err(InstanceRegistryError::OverlappingStorageRoots { .. })
        ));
    }

    #[test]
    fn rejects_missing_or_mismatched_primary() {
        let mut missing = config(vec![auxiliary("dev-dm", "/srv/openmp/dev-dm")]);
        missing.primary_instance = "main".into();
        assert!(matches!(
            ConfiguredInstanceRegistry::from_config(&missing),
            Err(InstanceRegistryError::PrimaryNotFound(_))
        ));

        let wrong_kind = auxiliary("main", "/srv/openmp/other-main");
        assert!(matches!(
            ConfiguredInstanceRegistry::from_config(&config(vec![wrong_kind])),
            Err(InstanceRegistryError::PrimaryKind(_))
        ));
    }

    #[test]
    fn rejects_duplicate_capabilities_and_orders_the_catalog() {
        let mut duplicated = auxiliary("dev-dm", "/srv/openmp/dev-dm");
        duplicated
            .capabilities
            .push(InstanceCapabilityConfig::Lifecycle);
        assert!(matches!(
            ConfiguredInstanceRegistry::from_config(&config(vec![primary(), duplicated])),
            Err(InstanceRegistryError::DuplicateCapability { .. })
        ));

        let mut later = auxiliary("later", "/srv/openmp/later");
        later.sort_order = 30;
        let mut earlier = auxiliary("earlier", "/srv/openmp/earlier");
        earlier.sort_order = 5;
        let registry =
            ConfiguredInstanceRegistry::from_config(&config(vec![later, primary(), earlier]))
                .unwrap();
        let ids: Vec<_> = registry
            .list()
            .into_iter()
            .map(|instance| instance.id().as_str().to_owned())
            .collect();
        assert_eq!(ids, ["earlier", "main", "later"]);
    }
}
