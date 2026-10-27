use std::collections::BTreeMap;

use serde::Serialize;
use utoipa::ToSchema;

use crate::server_instances::{
    application::manifest::{
        FeatureAccess, FeaturePermission, InstanceManifest, ManifestInstance, ManifestObservability,
    },
    application::runtime_state::RuntimeStateView,
    domain::{
        InstanceEnvironment, InstanceKind, InstanceManagement, InstanceReadiness,
        ObservationStatus, ProcessState, ReadinessStatus, TerminationEvidence, TerminationKind,
    },
};

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InstanceManifestResponse {
    pub schema_version: u16,
    pub revision: String,
    pub default_instance_id: String,
    pub instances: Vec<ManifestInstanceResponse>,
    pub unstable_features: BTreeMap<String, FeatureAccessResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestInstanceResponse {
    pub id: String,
    pub display_name: String,
    pub kind: InstanceKindResponse,
    pub environment: InstanceEnvironmentResponse,
    pub management: InstanceManagementResponse,
    pub sort_order: u32,
    pub features: BTreeMap<String, FeatureAccessResponse>,
    pub observability: ManifestObservabilityResponse,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FeatureAccessResponse {
    pub permissions: Vec<FeaturePermissionResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeaturePermissionResponse {
    Read,
    Write,
    UploadArtifact,
    Restore,
    Acknowledge,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestObservabilityResponse {
    pub process_monitoring: bool,
    pub readiness: InstanceReadinessResponse,
    pub incident_tracking: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum InstanceKindResponse {
    Primary,
    Auxiliary,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum InstanceEnvironmentResponse {
    Production,
    Development,
    Testing,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum InstanceManagementResponse {
    External,
    Systemd,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum InstanceReadinessResponse {
    Process,
    Uds,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStateResponse {
    pub schema_version: u16,
    pub instance_id: String,
    pub process: ProcessStateResponse,
    pub readiness: RuntimeReadinessResponse,
    pub observation: RuntimeObservationResponse,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProcessStateResponse {
    pub state: ProcessStatusResponse,
    pub main_pid: Option<u32>,
    pub restart_count: Option<u32>,
    pub invocation_id: Option<String>,
    pub last_termination: Option<TerminationEvidenceResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStatusResponse {
    Unknown,
    Inactive,
    Activating,
    Active,
    Deactivating,
    Failed,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeReadinessResponse {
    pub mode: InstanceReadinessResponse,
    pub status: ReadinessStatusResponse,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatusResponse {
    Unknown,
    NotReady,
    Ready,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeObservationResponse {
    pub status: ObservationStatusResponse,
    /// RFC 3339 UTC timestamp. Absent until the first observer snapshot.
    pub observed_at: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatusResponse {
    NotObserved,
    Observed,
    Stale,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TerminationEvidenceResponse {
    pub kind: TerminationKindResponse,
    pub status: Option<i32>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TerminationKindResponse {
    Clean,
    ExitCode,
    Signal,
    CoreDump,
    Timeout,
    Watchdog,
    ResourceFailure,
    StartLimit,
    Unknown,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServerInstanceErrorResponse {
    pub code: &'static str,
}

impl From<InstanceManifest> for InstanceManifestResponse {
    fn from(manifest: InstanceManifest) -> Self {
        Self {
            schema_version: manifest.schema_version,
            revision: manifest.revision,
            default_instance_id: manifest.default_instance_id.to_string(),
            instances: manifest.instances.into_iter().map(Into::into).collect(),
            unstable_features: manifest
                .unstable_features
                .into_iter()
                .map(|(id, access)| (id, access.into()))
                .collect(),
        }
    }
}

impl From<ManifestInstance> for ManifestInstanceResponse {
    fn from(instance: ManifestInstance) -> Self {
        Self {
            id: instance.id.to_string(),
            display_name: instance.display_name,
            kind: instance.kind.into(),
            environment: instance.environment.into(),
            management: instance.management.into(),
            sort_order: instance.sort_order,
            features: instance
                .features
                .into_iter()
                .map(|(id, access)| (id.as_str().to_owned(), access.into()))
                .collect(),
            observability: instance.observability.into(),
        }
    }
}

impl From<FeatureAccess> for FeatureAccessResponse {
    fn from(access: FeatureAccess) -> Self {
        Self {
            permissions: access.permissions.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<FeaturePermission> for FeaturePermissionResponse {
    fn from(permission: FeaturePermission) -> Self {
        match permission {
            FeaturePermission::Read => Self::Read,
            FeaturePermission::Write => Self::Write,
            FeaturePermission::UploadArtifact => Self::UploadArtifact,
            FeaturePermission::Restore => Self::Restore,
            FeaturePermission::Acknowledge => Self::Acknowledge,
        }
    }
}

impl From<ManifestObservability> for ManifestObservabilityResponse {
    fn from(observability: ManifestObservability) -> Self {
        Self {
            process_monitoring: observability.process_monitoring,
            readiness: observability.readiness.into(),
            incident_tracking: observability.incident_tracking,
        }
    }
}

impl From<InstanceKind> for InstanceKindResponse {
    fn from(kind: InstanceKind) -> Self {
        match kind {
            InstanceKind::Primary => Self::Primary,
            InstanceKind::Auxiliary => Self::Auxiliary,
        }
    }
}

impl From<InstanceEnvironment> for InstanceEnvironmentResponse {
    fn from(environment: InstanceEnvironment) -> Self {
        match environment {
            InstanceEnvironment::Production => Self::Production,
            InstanceEnvironment::Development => Self::Development,
            InstanceEnvironment::Testing => Self::Testing,
        }
    }
}

impl From<InstanceManagement> for InstanceManagementResponse {
    fn from(management: InstanceManagement) -> Self {
        match management {
            InstanceManagement::External => Self::External,
            InstanceManagement::Systemd => Self::Systemd,
        }
    }
}

impl From<InstanceReadiness> for InstanceReadinessResponse {
    fn from(readiness: InstanceReadiness) -> Self {
        match readiness {
            InstanceReadiness::Process => Self::Process,
            InstanceReadiness::Uds => Self::Uds,
        }
    }
}

impl From<RuntimeStateView> for RuntimeStateResponse {
    fn from(view: RuntimeStateView) -> Self {
        let state = view.state;
        Self {
            schema_version: 1,
            instance_id: state.instance_id().to_string(),
            process: ProcessStateResponse {
                state: state.process().into(),
                main_pid: state.main_pid(),
                restart_count: state.restart_count(),
                invocation_id: state.invocation_id().map(str::to_owned),
                last_termination: state.last_termination().map(Into::into),
            },
            readiness: RuntimeReadinessResponse {
                mode: view.readiness_mode.into(),
                status: state.readiness().into(),
            },
            observation: RuntimeObservationResponse {
                status: state.observation().into(),
                observed_at: state.observed_at().map(|value| value.to_rfc3339()),
            },
        }
    }
}

impl From<ProcessState> for ProcessStatusResponse {
    fn from(state: ProcessState) -> Self {
        match state {
            ProcessState::Unknown => Self::Unknown,
            ProcessState::Inactive => Self::Inactive,
            ProcessState::Activating => Self::Activating,
            ProcessState::Active => Self::Active,
            ProcessState::Deactivating => Self::Deactivating,
            ProcessState::Failed => Self::Failed,
        }
    }
}

impl From<ReadinessStatus> for ReadinessStatusResponse {
    fn from(status: ReadinessStatus) -> Self {
        match status {
            ReadinessStatus::Unknown => Self::Unknown,
            ReadinessStatus::NotReady => Self::NotReady,
            ReadinessStatus::Ready => Self::Ready,
        }
    }
}

impl From<ObservationStatus> for ObservationStatusResponse {
    fn from(status: ObservationStatus) -> Self {
        match status {
            ObservationStatus::NotObserved => Self::NotObserved,
            ObservationStatus::Observed => Self::Observed,
            ObservationStatus::Stale => Self::Stale,
        }
    }
}

impl From<&TerminationEvidence> for TerminationEvidenceResponse {
    fn from(evidence: &TerminationEvidence) -> Self {
        Self {
            kind: evidence.kind().into(),
            status: evidence.status(),
        }
    }
}

impl From<TerminationKind> for TerminationKindResponse {
    fn from(kind: TerminationKind) -> Self {
        match kind {
            TerminationKind::Clean => Self::Clean,
            TerminationKind::ExitCode => Self::ExitCode,
            TerminationKind::Signal => Self::Signal,
            TerminationKind::CoreDump => Self::CoreDump,
            TerminationKind::Timeout => Self::Timeout,
            TerminationKind::Watchdog => Self::Watchdog,
            TerminationKind::ResourceFailure => Self::ResourceFailure,
            TerminationKind::StartLimit => Self::StartLimit,
            TerminationKind::Unknown => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_names_are_stable_snake_case_values() {
        assert_eq!(
            serde_json::to_value(FeaturePermissionResponse::UploadArtifact).unwrap(),
            "upload_artifact"
        );
    }
}
