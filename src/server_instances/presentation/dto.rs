use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::server_instances::{
    application::lifecycle_operations::{
        LifecycleOperationListCursor, LifecycleOperationListQuery,
    },
    application::manifest::{
        FeatureAccess, FeaturePermission, InstanceManifest, ManifestInstance, ManifestObservability,
    },
    application::runtime_state::RuntimeStateView,
    domain::{
        InstanceEnvironment, InstanceKind, InstanceManagement, InstanceReadiness, LifecycleAction,
        LifecycleExpectedState, LifecycleFailureCode, LifecycleOperation,
        LifecycleOperationEvidence, LifecycleOperationId, LifecycleOperationState,
        ObservationStatus, ProcessState, ReadinessStatus, TerminationEvidence, TerminationKind,
    },
};

const DEFAULT_OPERATION_PAGE_SIZE: usize = 50;
const MAX_OPERATION_PAGE_SIZE: usize = 100;

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
    Start,
    Stop,
    Restart,
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateLifecycleOperationRequest {
    pub action: LifecycleActionRequest,
}

#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleActionRequest {
    Start,
    Stop,
    Restart,
}

impl From<LifecycleActionRequest> for LifecycleAction {
    fn from(value: LifecycleActionRequest) -> Self {
        match value {
            LifecycleActionRequest::Start => Self::Start,
            LifecycleActionRequest::Stop => Self::Stop,
            LifecycleActionRequest::Restart => Self::Restart,
        }
    }
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleOperationListParameters {
    /// RFC 3339 timestamp from `nextCursor.createdAt`.
    pub cursor_created_at: Option<String>,
    /// UUID from `nextCursor.operationId`.
    pub cursor_operation_id: Option<String>,
    /// Number of records, from 1 to 100. Defaults to 50.
    pub limit: Option<usize>,
}

impl LifecycleOperationListParameters {
    pub fn into_query(
        self,
    ) -> Result<LifecycleOperationListQuery, InvalidLifecycleOperationListParameters> {
        let limit = self.limit.unwrap_or(DEFAULT_OPERATION_PAGE_SIZE);
        if limit == 0 || limit > MAX_OPERATION_PAGE_SIZE {
            return Err(InvalidLifecycleOperationListParameters);
        }
        let cursor = match (self.cursor_created_at, self.cursor_operation_id) {
            (None, None) => None,
            (Some(created_at), Some(operation_id)) => Some(LifecycleOperationListCursor {
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at)
                    .map_err(|_| InvalidLifecycleOperationListParameters)?
                    .with_timezone(&chrono::Utc),
                operation_id: operation_id
                    .parse::<LifecycleOperationId>()
                    .map_err(|_| InvalidLifecycleOperationListParameters)?,
            }),
            _ => return Err(InvalidLifecycleOperationListParameters),
        };
        LifecycleOperationListQuery::new(cursor, limit)
            .map_err(|_| InvalidLifecycleOperationListParameters)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InvalidLifecycleOperationListParameters;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleOperationListResponse {
    pub operations: Vec<LifecycleOperationResponse>,
    pub next_cursor: Option<LifecycleOperationCursorResponse>,
}

impl LifecycleOperationListResponse {
    pub fn from_operations(operations: &[LifecycleOperation]) -> Self {
        let next_cursor = operations
            .last()
            .map(|operation| LifecycleOperationCursorResponse {
                created_at: operation.created_at().to_rfc3339(),
                operation_id: operation.id().to_string(),
            });
        Self {
            operations: operations
                .iter()
                .map(LifecycleOperationResponse::from)
                .collect(),
            next_cursor,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleOperationCursorResponse {
    pub created_at: String,
    pub operation_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleOperationResponse {
    pub schema_version: u16,
    pub id: String,
    pub instance_id: String,
    pub action: LifecycleActionResponse,
    pub actor_user_id: i64,
    pub actor_display_name: String,
    pub status: LifecycleOperationStatusResponse,
    pub expected_state: LifecycleExpectedStateResponse,
    pub systemd_job: Option<String>,
    pub failure_code: Option<LifecycleFailureCodeResponse>,
    pub initial_evidence: LifecycleEvidenceResponse,
    pub final_evidence: Option<LifecycleEvidenceResponse>,
    pub created_at: String,
    pub updated_at: String,
    pub deadline: String,
    pub completed_at: Option<String>,
    pub version: u64,
}

impl From<&LifecycleOperation> for LifecycleOperationResponse {
    fn from(operation: &LifecycleOperation) -> Self {
        let (status, systemd_job, failure_code) = match operation.state() {
            LifecycleOperationState::Requested => {
                (LifecycleOperationStatusResponse::Requested, None, None)
            }
            LifecycleOperationState::Dispatching => {
                (LifecycleOperationStatusResponse::Dispatching, None, None)
            }
            LifecycleOperationState::WaitingForState { job } => (
                LifecycleOperationStatusResponse::WaitingForState,
                Some(job.as_str().to_owned()),
                None,
            ),
            LifecycleOperationState::Succeeded => {
                (LifecycleOperationStatusResponse::Succeeded, None, None)
            }
            LifecycleOperationState::Failed { code } => (
                LifecycleOperationStatusResponse::Failed,
                None,
                Some((*code).into()),
            ),
            LifecycleOperationState::TimedOut => {
                (LifecycleOperationStatusResponse::TimedOut, None, None)
            }
        };
        Self {
            schema_version: 1,
            id: operation.id().to_string(),
            instance_id: operation.instance_id().to_string(),
            action: operation.action().into(),
            actor_user_id: operation.actor_id().get(),
            actor_display_name: operation.actor_display_name().to_owned(),
            status,
            expected_state: operation.expected_state().into(),
            systemd_job,
            failure_code,
            initial_evidence: operation.initial_evidence().into(),
            final_evidence: operation.final_evidence().map(Into::into),
            created_at: operation.created_at().to_rfc3339(),
            updated_at: operation.updated_at().to_rfc3339(),
            deadline: operation.deadline().to_rfc3339(),
            completed_at: operation.completed_at().map(|value| value.to_rfc3339()),
            version: operation.version().get(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleActionResponse {
    Start,
    Stop,
    Restart,
}

impl From<LifecycleAction> for LifecycleActionResponse {
    fn from(value: LifecycleAction) -> Self {
        match value {
            LifecycleAction::Start => Self::Start,
            LifecycleAction::Stop => Self::Stop,
            LifecycleAction::Restart => Self::Restart,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleOperationStatusResponse {
    Requested,
    Dispatching,
    WaitingForState,
    Succeeded,
    Failed,
    TimedOut,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleExpectedStateResponse {
    Active,
    Inactive,
}

impl From<LifecycleExpectedState> for LifecycleExpectedStateResponse {
    fn from(value: LifecycleExpectedState) -> Self {
        match value {
            LifecycleExpectedState::Active => Self::Active,
            LifecycleExpectedState::Inactive => Self::Inactive,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleFailureCodeResponse {
    RuntimeUnavailable,
    RuntimeRejected,
    ObservationUnavailable,
    UnexpectedFinalState,
    ReconciliationFailed,
}

impl From<LifecycleFailureCode> for LifecycleFailureCodeResponse {
    fn from(value: LifecycleFailureCode) -> Self {
        match value {
            LifecycleFailureCode::RuntimeUnavailable => Self::RuntimeUnavailable,
            LifecycleFailureCode::RuntimeRejected => Self::RuntimeRejected,
            LifecycleFailureCode::ObservationUnavailable => Self::ObservationUnavailable,
            LifecycleFailureCode::UnexpectedFinalState => Self::UnexpectedFinalState,
            LifecycleFailureCode::ReconciliationFailed => Self::ReconciliationFailed,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleEvidenceResponse {
    pub process: ProcessStatusResponse,
    pub readiness: ReadinessStatusResponse,
    pub observation: ObservationStatusResponse,
    pub observed_at: Option<String>,
    pub restart_count: Option<u32>,
    pub invocation_id: Option<String>,
}

impl From<&LifecycleOperationEvidence> for LifecycleEvidenceResponse {
    fn from(value: &LifecycleOperationEvidence) -> Self {
        Self {
            process: value.process().into(),
            readiness: value.readiness().into(),
            observation: value.observation().into(),
            observed_at: value.observed_at().map(|at| at.to_rfc3339()),
            restart_count: value.restart_count(),
            invocation_id: value.invocation_id().map(str::to_owned),
        }
    }
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
            FeaturePermission::Start => Self::Start,
            FeaturePermission::Stop => Self::Stop,
            FeaturePermission::Restart => Self::Restart,
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

    #[test]
    fn lifecycle_cursor_requires_both_parts_and_a_bounded_limit() {
        assert!(
            LifecycleOperationListParameters {
                cursor_created_at: Some("2026-10-27T12:00:00Z".into()),
                cursor_operation_id: None,
                limit: Some(50),
            }
            .into_query()
            .is_err()
        );
        assert!(
            LifecycleOperationListParameters {
                cursor_created_at: None,
                cursor_operation_id: None,
                limit: Some(101),
            }
            .into_query()
            .is_err()
        );
        let operation_id = LifecycleOperationId::new();
        let query = LifecycleOperationListParameters {
            cursor_created_at: Some("2026-10-27T12:00:00Z".into()),
            cursor_operation_id: Some(operation_id.to_string()),
            limit: None,
        }
        .into_query()
        .unwrap();
        assert_eq!(query.limit, DEFAULT_OPERATION_PAGE_SIZE);
        assert_eq!(query.cursor.unwrap().operation_id, operation_id);
    }
}
