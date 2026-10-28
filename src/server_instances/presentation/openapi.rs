use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use super::dto::{
    CreateLifecycleOperationRequest, FeatureAccessResponse, FeaturePermissionResponse,
    InstanceEnvironmentResponse, InstanceKindResponse, InstanceManagementResponse,
    InstanceManifestResponse, InstanceReadinessResponse, LifecycleActionRequest,
    LifecycleActionResponse, LifecycleEvidenceResponse, LifecycleExpectedStateResponse,
    LifecycleFailureCodeResponse, LifecycleOperationCursorResponse, LifecycleOperationListResponse,
    LifecycleOperationResponse, LifecycleOperationStatusResponse, ManifestInstanceResponse,
    ManifestObservabilityResponse, ObservationStatusResponse, ProcessStateResponse,
    ProcessStatusResponse, ReadinessStatusResponse, RuntimeObservationResponse,
    RuntimeReadinessResponse, RuntimeStateResponse, ServerInstanceErrorResponse,
    TerminationEvidenceResponse, TerminationKindResponse,
};

const BEARER_AUTH_SCHEME: &str = "bearerAuth";

#[derive(OpenApi)]
#[openapi(
    components(schemas(
        InstanceManifestResponse,
        ManifestInstanceResponse,
        FeatureAccessResponse,
        FeaturePermissionResponse,
        ManifestObservabilityResponse,
        InstanceKindResponse,
        InstanceEnvironmentResponse,
        InstanceManagementResponse,
        InstanceReadinessResponse,
        RuntimeStateResponse,
        ProcessStateResponse,
        ProcessStatusResponse,
        RuntimeReadinessResponse,
        ReadinessStatusResponse,
        RuntimeObservationResponse,
        ObservationStatusResponse,
        TerminationEvidenceResponse,
        TerminationKindResponse,
        CreateLifecycleOperationRequest,
        LifecycleActionRequest,
        LifecycleOperationListResponse,
        LifecycleOperationCursorResponse,
        LifecycleOperationResponse,
        LifecycleActionResponse,
        LifecycleOperationStatusResponse,
        LifecycleExpectedStateResponse,
        LifecycleFailureCodeResponse,
        LifecycleEvidenceResponse,
        ServerInstanceErrorResponse
    )),
    modifiers(&BearerSecurity),
    tags((
        name = "Server instances",
        description = "Personalized catalog of managed game-server instances and their effective capabilities."
    ))
)]
struct ServerInstancesApiDoc;

struct BearerSecurity;

impl Modify for BearerSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                BEARER_AUTH_SCHEME,
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}

pub fn base_document() -> utoipa::openapi::OpenApi {
    ServerInstancesApiDoc::openapi()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use utoipa_axum::router::OpenApiRouter;

    use super::*;
    use crate::{
        auth::{
            application::authenticate_jwt::AuthenticateBearerToken,
            presentation::extractors::JwtExtractorState,
        },
        server_instances::{
            application::{
                lifecycle_service::LifecycleOperationService, registry::InstanceRegistry,
                runtime_state::RuntimeStateReader,
            },
            presentation::state::ServerInstancesState,
        },
    };

    #[derive(Clone)]
    struct DocumentationState;

    impl JwtExtractorState for DocumentationState {
        fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
            panic!("documentation generation does not resolve authentication")
        }
    }

    impl ServerInstancesState for DocumentationState {
        fn instance_registry(&self) -> Arc<dyn InstanceRegistry> {
            panic!("documentation generation does not resolve application ports")
        }

        fn runtime_state_reader(&self) -> Arc<dyn RuntimeStateReader> {
            panic!("documentation generation does not resolve application ports")
        }

        fn lifecycle_operation_service(&self) -> Arc<LifecycleOperationService> {
            panic!("documentation generation does not resolve application services")
        }
    }

    #[test]
    fn documents_the_protected_manifest_contract() {
        let document = OpenApiRouter::<DocumentationState>::with_openapi(base_document())
            .merge(super::super::routes::router())
            .into_openapi();
        let specification = serde_json::to_value(document).unwrap();
        let operation = &specification["paths"]["/server-instances"]["get"];

        assert!(operation.is_object());
        assert_eq!(
            operation["security"][0][BEARER_AUTH_SCHEME],
            serde_json::json!([])
        );
        assert!(specification["components"]["schemas"]["InstanceManifestResponse"].is_object());
        assert!(specification["paths"]["/server-instances/{instance_id}/state"]["get"].is_object());
        assert!(specification["components"]["schemas"]["RuntimeStateResponse"].is_object());
        assert!(
            specification["paths"]["/server-instances/{instance_id}/operations"]["post"]
                .is_object()
        );
        assert!(
            specification["paths"]["/server-instances/{instance_id}/operations"]["get"].is_object()
        );
        assert!(
            specification["paths"]
                ["/server-instances/{instance_id}/operations/{operation_id}"]["get"]
                .is_object()
        );
        assert!(specification["components"]["schemas"]["LifecycleOperationResponse"].is_object());
    }
}
