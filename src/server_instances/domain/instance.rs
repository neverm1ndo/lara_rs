use thiserror::Error;

use super::{InstanceCapabilities, InstanceCapability};

const MAX_INSTANCE_ID_LENGTH: usize = 64;
const MAX_DISPLAY_NAME_LENGTH: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerInstanceId(String);

impl ServerInstanceId {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidServerInstance> {
        let value = value.into();
        let bytes = value.as_bytes();
        let valid = !bytes.is_empty()
            && bytes.len() <= MAX_INSTANCE_ID_LENGTH
            && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');

        if !valid {
            return Err(InvalidServerInstance::Identifier(value));
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ServerInstanceId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceKind {
    Primary,
    Auxiliary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceEnvironment {
    Production,
    Development,
    Testing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceReadiness {
    Process,
    Uds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceObservability {
    readiness: InstanceReadiness,
    incident_tracking: bool,
}

impl InstanceObservability {
    pub const fn new(readiness: InstanceReadiness, incident_tracking: bool) -> Self {
        Self {
            readiness,
            incident_tracking,
        }
    }

    pub const fn readiness(self) -> InstanceReadiness {
        self.readiness
    }

    pub const fn incident_tracking(self) -> bool {
        self.incident_tracking
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInstance {
    id: ServerInstanceId,
    display_name: String,
    kind: InstanceKind,
    environment: InstanceEnvironment,
    sort_order: u32,
    capabilities: InstanceCapabilities,
    observability: InstanceObservability,
}

impl ServerInstance {
    pub fn new(
        id: ServerInstanceId,
        display_name: impl Into<String>,
        kind: InstanceKind,
        environment: InstanceEnvironment,
        sort_order: u32,
        capabilities: InstanceCapabilities,
        observability: InstanceObservability,
    ) -> Result<Self, InvalidServerInstance> {
        let display_name = display_name.into();
        let trimmed = display_name.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_DISPLAY_NAME_LENGTH {
            return Err(InvalidServerInstance::DisplayName);
        }
        if !capabilities.contains(InstanceCapability::Lifecycle) {
            return Err(InvalidServerInstance::MissingLifecycle);
        }
        match kind {
            InstanceKind::Primary => {
                let required = InstanceCapabilities::primary();
                if required
                    .iter()
                    .any(|capability| !capabilities.contains(capability))
                {
                    return Err(InvalidServerInstance::IncompletePrimaryCapabilities);
                }
            }
            InstanceKind::Auxiliary => {
                if capabilities.contains(InstanceCapability::Backups) {
                    return Err(InvalidServerInstance::AuxiliaryBackups);
                }
                if capabilities.contains(InstanceCapability::Maps) {
                    return Err(InvalidServerInstance::AuxiliaryMaps);
                }
            }
        }

        Ok(Self {
            id,
            display_name: trimmed.to_owned(),
            kind,
            environment,
            sort_order,
            capabilities,
            observability,
        })
    }

    pub fn id(&self) -> &ServerInstanceId {
        &self.id
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub const fn kind(&self) -> InstanceKind {
        self.kind
    }

    pub const fn environment(&self) -> InstanceEnvironment {
        self.environment
    }

    pub const fn sort_order(&self) -> u32 {
        self.sort_order
    }

    pub fn capabilities(&self) -> &InstanceCapabilities {
        &self.capabilities
    }

    pub const fn observability(&self) -> InstanceObservability {
        self.observability
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum InvalidServerInstance {
    #[error("invalid server instance identifier `{0}`")]
    Identifier(String),
    #[error("server instance display name must contain between 1 and 100 bytes")]
    DisplayName,
    #[error("every managed server instance requires the lifecycle capability")]
    MissingLifecycle,
    #[error("the primary server instance requires every supported capability")]
    IncompletePrimaryCapabilities,
    #[error("auxiliary server instances cannot enable backups")]
    AuxiliaryBackups,
    #[error("auxiliary server instances cannot enable maps")]
    AuxiliaryMaps,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auxiliary(capabilities: impl IntoIterator<Item = InstanceCapability>) -> ServerInstance {
        ServerInstance::new(
            ServerInstanceId::new("dev-dm").unwrap(),
            "Developer DM",
            InstanceKind::Auxiliary,
            InstanceEnvironment::Development,
            20,
            InstanceCapabilities::new(capabilities),
            InstanceObservability::new(InstanceReadiness::Process, true),
        )
        .unwrap()
    }

    #[test]
    fn validates_stable_identifiers() {
        for valid in ["main", "dev-dm", "server2", "2-test"] {
            assert_eq!(ServerInstanceId::new(valid).unwrap().as_str(), valid);
        }
        for invalid in ["", "Main", "dev_dm", "-dev", "dev-", "dev dm", "я"] {
            assert!(ServerInstanceId::new(invalid).is_err());
        }
    }

    #[test]
    fn accepts_auxiliary_configuration_without_backups() {
        let instance = auxiliary([
            InstanceCapability::Overview,
            InstanceCapability::Lifecycle,
            InstanceCapability::Configuration,
            InstanceCapability::Incidents,
        ]);

        assert_eq!(instance.kind(), InstanceKind::Auxiliary);
        assert!(
            instance
                .capabilities()
                .contains(InstanceCapability::Configuration)
        );
        assert!(
            !instance
                .capabilities()
                .contains(InstanceCapability::Backups)
        );
    }

    #[test]
    fn rejects_forbidden_auxiliary_capabilities() {
        for forbidden in [InstanceCapability::Maps, InstanceCapability::Backups] {
            let result = ServerInstance::new(
                ServerInstanceId::new("dev-dm").unwrap(),
                "Developer DM",
                InstanceKind::Auxiliary,
                InstanceEnvironment::Development,
                20,
                InstanceCapabilities::new([InstanceCapability::Lifecycle, forbidden]),
                InstanceObservability::new(InstanceReadiness::Process, true),
            );
            assert!(result.is_err());
        }
    }

    #[test]
    fn primary_requires_the_full_capability_set() {
        let result = ServerInstance::new(
            ServerInstanceId::new("main").unwrap(),
            "Main",
            InstanceKind::Primary,
            InstanceEnvironment::Production,
            10,
            InstanceCapabilities::new([InstanceCapability::Lifecycle]),
            InstanceObservability::new(InstanceReadiness::Uds, true),
        );

        assert_eq!(
            result,
            Err(InvalidServerInstance::IncompletePrimaryCapabilities)
        );
    }
}
