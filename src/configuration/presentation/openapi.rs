use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use super::dto::{
    ConfigurationTreeEntryKindResponse, ConfigurationTreeEntryResponse, ConfigurationTreeResponse,
    ErrorResponse, FileMutationResponse, RenameFileRequest, WriteFileRequest,
};

const BEARER_AUTH_SCHEME: &str = "bearerAuth";

#[derive(OpenApi)]
#[openapi(
    components(schemas(
        ConfigurationTreeResponse,
        ConfigurationTreeEntryResponse,
        ConfigurationTreeEntryKindResponse,
        WriteFileRequest,
        RenameFileRequest,
        FileMutationResponse,
        ErrorResponse
    )),
    modifiers(&BearerSecurity),
    tags((
        name = "Server configuration",
        description = "Manage SAMP/open.mp configuration files within a role-scoped filesystem capability"
    ))
)]
struct ConfigurationApiDoc;

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
                        .description(Some(
                            "JWT returned by POST /auth/login. Developer or configurator membership is required."
                                .to_owned(),
                        ))
                        .build(),
                ),
            );
        }
    }
}

pub fn base_document() -> utoipa::openapi::OpenApi {
    ConfigurationApiDoc::openapi()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use utoipa_axum::router::OpenApiRouter;

    use crate::{
        auth::{
            application::authenticate_jwt::AuthenticateBearerToken,
            presentation::extractors::JwtExtractorState,
        },
        configuration::{
            application::file_service::ConfigurationFileService,
            presentation::{
                authorization::ConfigurationAuthorizationState, state::ConfigurationState,
            },
        },
        shared::file_storage::path::RelativeStoragePath,
    };

    use super::*;

    #[derive(Clone)]
    struct DocumentationState;

    impl JwtExtractorState for DocumentationState {
        fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
            panic!("documentation generation does not resolve authentication")
        }
    }

    impl ConfigurationAuthorizationState for DocumentationState {
        fn configurator_directory(&self) -> &RelativeStoragePath {
            panic!("documentation generation does not resolve configuration")
        }
    }

    impl ConfigurationState for DocumentationState {
        fn configuration_file_service(&self) -> Arc<dyn ConfigurationFileService> {
            panic!("documentation generation does not resolve application services")
        }
    }

    fn document() -> utoipa::openapi::OpenApi {
        OpenApiRouter::<DocumentationState>::with_openapi(base_document())
            .nest("/configuration", super::super::routes::router())
            .into_openapi()
    }

    #[test]
    fn documents_all_configuration_routes_as_openapi_3_1() {
        let specification = serde_json::to_value(document()).unwrap();

        assert_eq!(specification["openapi"], "3.1.0");
        assert!(specification["paths"]["/configuration/tree"]["get"].is_object());

        let files = &specification["paths"]["/configuration/files"];
        for method in ["get", "post", "put", "delete"] {
            assert!(
                files[method].is_object(),
                "missing {method} /configuration/files"
            );
            assert_eq!(
                files[method]["security"][0][BEARER_AUTH_SCHEME],
                serde_json::json!([])
            );
        }
        assert!(specification["paths"]["/configuration/files/rename"]["patch"].is_object());
        assert_eq!(
            specification["components"]["securitySchemes"][BEARER_AUTH_SCHEME]["scheme"],
            "bearer"
        );
        assert_eq!(
            files["get"]["responses"]["200"]["content"]["text/plain"]["schema"]["type"],
            "string"
        );
    }
}
