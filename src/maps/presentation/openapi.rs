use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use super::dto::{
    MapFileMutationResponse, MapFileMutationsResponse, MapFilesUpload, MapsErrorResponse,
    MapsTreeEntryKindResponse, MapsTreeEntryResponse, MapsTreeResponse, RenameMapFileRequest,
};

const BEARER_AUTH_SCHEME: &str = "bearerAuth";

#[derive(OpenApi)]
#[openapi(
    components(schemas(
        MapsTreeResponse,
        MapsTreeEntryResponse,
        MapsTreeEntryKindResponse,
        MapFilesUpload,
        RenameMapFileRequest,
        MapFileMutationResponse,
        MapFileMutationsResponse,
        MapsErrorResponse
    )),
    modifiers(&BearerSecurity),
    tags((
        name = "Server maps",
        description = "Manage nested SAMP/open.mp .map and .map.off files"
    ))
)]
struct MapsApiDoc;

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
                            "JWT returned by POST /auth/login. Developer or mapper membership is required."
                                .to_owned(),
                        ))
                        .build(),
                ),
            );
        }
    }
}

pub fn base_document() -> utoipa::openapi::OpenApi {
    MapsApiDoc::openapi()
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
        maps::{application::file_service::MapsFileService, presentation::state::MapsState},
        shared::file_storage::upload::MultipartUploadLimits,
    };

    #[derive(Clone)]
    struct DocumentationState;

    impl JwtExtractorState for DocumentationState {
        fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
            panic!("documentation generation does not resolve authentication")
        }
    }

    impl MapsState for DocumentationState {
        fn maps_file_service(&self) -> Arc<dyn MapsFileService> {
            panic!("documentation generation does not resolve application services")
        }

        fn maps_upload_limits(&self) -> MultipartUploadLimits {
            MultipartUploadLimits::new(50, 10 * 1024 * 1024, 50 * 1024 * 1024).unwrap()
        }
    }

    fn document() -> utoipa::openapi::OpenApi {
        OpenApiRouter::<DocumentationState>::with_openapi(base_document())
            .nest("/maps", super::super::routes::router())
            .into_openapi()
    }

    #[test]
    fn documents_all_maps_routes_as_openapi_3_1() {
        let specification = serde_json::to_value(document()).unwrap();

        assert_eq!(specification["openapi"], "3.1.0");
        assert!(specification["paths"]["/maps/tree"]["get"].is_object());
        let files = &specification["paths"]["/maps/files"];
        for method in ["get", "post", "put", "delete"] {
            assert!(files[method].is_object(), "missing {method} /maps/files");
            assert_eq!(
                files[method]["security"][0][BEARER_AUTH_SCHEME],
                serde_json::json!([])
            );
        }
        assert!(specification["paths"]["/maps/files/rename"]["patch"].is_object());
        assert_eq!(
            specification["components"]["securitySchemes"][BEARER_AUTH_SCHEME]["scheme"],
            "bearer"
        );
        for method in ["post", "put"] {
            assert!(files[method]["requestBody"]["content"]["multipart/form-data"].is_object());
        }
    }
}
