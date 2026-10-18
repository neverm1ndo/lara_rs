use std::collections::BTreeMap;

use serde::Serialize;
use utoipa::ToSchema;

use crate::server_instances::{
    application::manifest::{
        FeatureAccess, FeaturePermission, InstanceManifest, ManifestInstance, ManifestObservability,
    },
    domain::{InstanceEnvironment, InstanceKind, InstanceReadiness},
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
pub enum InstanceReadinessResponse {
    Process,
    Uds,
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

impl From<InstanceReadiness> for InstanceReadinessResponse {
    fn from(readiness: InstanceReadiness) -> Self {
        match readiness {
            InstanceReadiness::Process => Self::Process,
            InstanceReadiness::Uds => Self::Uds,
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
