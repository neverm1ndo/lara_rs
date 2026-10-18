use std::{collections::BTreeMap, sync::Arc};

use sha2::{Digest, Sha256};

use crate::{
    server_instances::{
        application::registry::InstanceRegistry,
        domain::{
            InstanceCapability, InstanceEnvironment, InstanceKind, InstanceReadiness,
            ServerInstance, ServerInstanceId,
        },
    },
    shared::user_role::UserRole,
};

pub const MANIFEST_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone)]
pub struct ManifestSubject {
    main_group: UserRole,
    permissions: Vec<UserRole>,
}

impl ManifestSubject {
    pub fn new(main_group: UserRole, permissions: Vec<UserRole>) -> Self {
        Self {
            main_group,
            permissions,
        }
    }

    fn has_role(&self, role: UserRole) -> bool {
        self.main_group == role || self.permissions.contains(&role)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceManifest {
    pub schema_version: u16,
    pub revision: String,
    pub default_instance_id: ServerInstanceId,
    pub instances: Vec<ManifestInstance>,
    pub unstable_features: BTreeMap<String, FeatureAccess>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestInstance {
    pub id: ServerInstanceId,
    pub display_name: String,
    pub kind: InstanceKind,
    pub environment: InstanceEnvironment,
    pub sort_order: u32,
    pub features: BTreeMap<FeatureId, FeatureAccess>,
    pub observability: ManifestObservability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestObservability {
    pub process_monitoring: bool,
    pub readiness: InstanceReadiness,
    pub incident_tracking: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FeatureId {
    Overview,
    Lifecycle,
    Configuration,
    Maps,
    Backups,
    Incidents,
}

impl FeatureId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Overview => "lara.overview.v1",
            Self::Lifecycle => "lara.lifecycle.v1",
            Self::Configuration => "lara.configuration.v1",
            Self::Maps => "lara.maps.v1",
            Self::Backups => "lara.backups.v1",
            Self::Incidents => "lara.incidents.v1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureAccess {
    pub permissions: Vec<FeaturePermission>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FeaturePermission {
    Read,
    Write,
    UploadArtifact,
    Restore,
    Acknowledge,
}

impl FeaturePermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::UploadArtifact => "upload_artifact",
            Self::Restore => "restore",
            Self::Acknowledge => "acknowledge",
        }
    }
}

pub struct InstanceManifestService {
    registry: Arc<dyn InstanceRegistry>,
}

impl InstanceManifestService {
    pub fn new(registry: Arc<dyn InstanceRegistry>) -> Self {
        Self { registry }
    }

    pub fn get(&self, subject: &ManifestSubject) -> InstanceManifest {
        let developer = subject.has_role(UserRole::Developer);
        let source = if developer {
            self.registry.list()
        } else {
            vec![self.registry.primary()]
        };
        let instances = source
            .into_iter()
            .map(|instance| project_instance(instance, subject, developer))
            .collect();
        let mut manifest = InstanceManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            revision: String::new(),
            default_instance_id: self.registry.primary().id().clone(),
            instances,
            unstable_features: BTreeMap::new(),
        };
        manifest.revision = revision(&manifest);
        manifest
    }
}

fn project_instance(
    instance: ServerInstance,
    subject: &ManifestSubject,
    developer: bool,
) -> ManifestInstance {
    let features = instance
        .capabilities()
        .iter()
        .filter_map(|capability| {
            permissions_for(capability, subject, developer)
                .map(|access| (feature_id(capability), access))
        })
        .collect();
    let observability = instance.observability();

    ManifestInstance {
        id: instance.id().clone(),
        display_name: instance.display_name().to_owned(),
        kind: instance.kind(),
        environment: instance.environment(),
        sort_order: instance.sort_order(),
        features,
        observability: ManifestObservability {
            process_monitoring: true,
            readiness: observability.readiness(),
            incident_tracking: observability.incident_tracking(),
        },
    }
}

fn permissions_for(
    capability: InstanceCapability,
    subject: &ManifestSubject,
    developer: bool,
) -> Option<FeatureAccess> {
    let permissions = match capability {
        InstanceCapability::Overview => vec![FeaturePermission::Read],
        InstanceCapability::Lifecycle if developer => vec![FeaturePermission::Read],
        InstanceCapability::Configuration if developer => vec![
            FeaturePermission::Read,
            FeaturePermission::Write,
            FeaturePermission::UploadArtifact,
        ],
        InstanceCapability::Configuration if subject.has_role(UserRole::Configurator) => {
            vec![FeaturePermission::Read, FeaturePermission::Write]
        }
        InstanceCapability::Maps if developer || subject.has_role(UserRole::Mapper) => {
            vec![FeaturePermission::Read, FeaturePermission::Write]
        }
        InstanceCapability::Backups if developer || subject.has_role(UserRole::Backuper) => {
            vec![FeaturePermission::Read, FeaturePermission::Restore]
        }
        InstanceCapability::Incidents if developer => {
            vec![FeaturePermission::Read, FeaturePermission::Acknowledge]
        }
        _ => return None,
    };

    Some(FeatureAccess { permissions })
}

const fn feature_id(capability: InstanceCapability) -> FeatureId {
    match capability {
        InstanceCapability::Overview => FeatureId::Overview,
        InstanceCapability::Lifecycle => FeatureId::Lifecycle,
        InstanceCapability::Configuration => FeatureId::Configuration,
        InstanceCapability::Maps => FeatureId::Maps,
        InstanceCapability::Backups => FeatureId::Backups,
        InstanceCapability::Incidents => FeatureId::Incidents,
    }
}

fn revision(manifest: &InstanceManifest) -> String {
    let mut digest = Sha256::new();
    digest.update(manifest.schema_version.to_be_bytes());
    digest.update(manifest.default_instance_id.as_str());
    for instance in &manifest.instances {
        digest.update(instance.id.as_str());
        digest.update(instance.display_name.as_bytes());
        digest.update(format!("{:?}{:?}", instance.kind, instance.environment));
        digest.update(instance.sort_order.to_be_bytes());
        digest.update(format!("{:?}", instance.observability));
        for (feature, access) in &instance.features {
            digest.update(feature.as_str());
            for permission in &access.permissions {
                digest.update(permission.as_str());
            }
        }
    }
    for (feature, access) in &manifest.unstable_features {
        digest.update(feature.as_bytes());
        for permission in &access.permissions {
            digest.update(permission.as_str());
        }
    }
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_instances::domain::{InstanceCapabilities, InstanceObservability};

    struct MemoryRegistry {
        instances: Vec<ServerInstance>,
    }

    impl InstanceRegistry for MemoryRegistry {
        fn primary(&self) -> ServerInstance {
            self.instances[0].clone()
        }

        fn get(&self, id: &ServerInstanceId) -> Option<ServerInstance> {
            self.instances.iter().find(|item| item.id() == id).cloned()
        }

        fn list(&self) -> Vec<ServerInstance> {
            self.instances.clone()
        }
    }

    fn primary() -> ServerInstance {
        ServerInstance::new(
            ServerInstanceId::new("main").unwrap(),
            "Main",
            InstanceKind::Primary,
            InstanceEnvironment::Production,
            10,
            InstanceCapabilities::primary(),
            InstanceObservability::new(InstanceReadiness::Uds, true),
        )
        .unwrap()
    }

    fn auxiliary() -> ServerInstance {
        ServerInstance::new(
            ServerInstanceId::new("dev-dm").unwrap(),
            "Developer DM",
            InstanceKind::Auxiliary,
            InstanceEnvironment::Development,
            20,
            InstanceCapabilities::new([
                InstanceCapability::Overview,
                InstanceCapability::Lifecycle,
                InstanceCapability::Configuration,
                InstanceCapability::Incidents,
            ]),
            InstanceObservability::new(InstanceReadiness::Process, true),
        )
        .unwrap()
    }

    fn service() -> InstanceManifestService {
        InstanceManifestService::new(Arc::new(MemoryRegistry {
            instances: vec![primary(), auxiliary()],
        }))
    }

    fn subject(role: UserRole) -> ManifestSubject {
        ManifestSubject::new(role, vec![role])
    }

    #[test]
    fn developer_sees_every_instance_and_declared_feature() {
        let manifest = service().get(&subject(UserRole::Developer));

        assert_eq!(manifest.instances.len(), 2);
        assert_eq!(manifest.instances[1].id.as_str(), "dev-dm");
        assert_eq!(manifest.instances[1].features.len(), 4);
        assert_eq!(
            manifest.instances[1].features[&FeatureId::Lifecycle].permissions,
            [FeaturePermission::Read]
        );
        assert!(
            !manifest.instances[1]
                .features
                .contains_key(&FeatureId::Backups)
        );
    }

    #[test]
    fn specialized_roles_only_receive_their_primary_feature_and_overview() {
        for (role, expected) in [
            (UserRole::Configurator, FeatureId::Configuration),
            (UserRole::Mapper, FeatureId::Maps),
            (UserRole::Backuper, FeatureId::Backups),
        ] {
            let manifest = service().get(&subject(role));
            let features = &manifest.instances[0].features;

            assert_eq!(manifest.instances.len(), 1, "role: {role:?}");
            assert_eq!(features.len(), 2, "role: {role:?}");
            assert!(features.contains_key(&FeatureId::Overview));
            assert!(features.contains_key(&expected));
            assert!(!features.contains_key(&FeatureId::Lifecycle));
        }
    }

    #[test]
    fn challenger_and_admin_only_receive_primary_overview() {
        for role in [UserRole::Challenger, UserRole::Admin] {
            let manifest = service().get(&subject(role));
            let features = &manifest.instances[0].features;

            assert_eq!(manifest.instances.len(), 1);
            assert_eq!(
                features.keys().copied().collect::<Vec<_>>(),
                [FeatureId::Overview]
            );
        }
    }

    #[test]
    fn developer_permission_takes_precedence_over_main_group() {
        let manifest = service().get(&ManifestSubject::new(
            UserRole::Admin,
            vec![UserRole::Admin, UserRole::Developer],
        ));

        assert_eq!(manifest.instances.len(), 2);
        assert!(
            manifest.instances[0]
                .features
                .contains_key(&FeatureId::Lifecycle)
        );
    }

    #[test]
    fn revision_is_stable_and_personalized() {
        let service = service();
        let first = service.get(&subject(UserRole::Developer));
        let second = service.get(&subject(UserRole::Developer));
        let admin = service.get(&subject(UserRole::Admin));

        assert_eq!(first.revision, second.revision);
        assert_eq!(first.revision.len(), 64);
        assert_ne!(first.revision, admin.revision);
    }
}
