use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use super::dto::{
    FeatureAccessResponse, FeaturePermissionResponse, InstanceEnvironmentResponse,
    InstanceKindResponse, InstanceManifestResponse, InstanceReadinessResponse,
    ManifestInstanceResponse, ManifestObservabilityResponse, ObservationStatusResponse,
    ProcessStateResponse, ProcessStatusResponse, ReadinessStatusResponse,
    RuntimeObservationResponse, RuntimeReadinessResponse, RuntimeStateResponse,
    ServerInstanceErrorResponse, TerminationEvidenceResponse, TerminationKindResponse,
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
            application::{registry::InstanceRegistry, runtime_state::RuntimeStateReader},
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
    }
}
