use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use super::dto::{
    BackupActionResponse, BackupCursorResponse, BackupDiffResponse, BackupDiffSkipReasonResponse,
    BackupListResponse, BackupResponse, BackupSnapshotResponse, BackupStateResponse,
    BackupsErrorResponse, SnapshotCompressionResponse,
};

const BEARER_AUTH_SCHEME: &str = "bearerAuth";

#[derive(OpenApi)]
#[openapi(
    components(schemas(
        BackupListResponse,
        BackupCursorResponse,
        BackupResponse,
        BackupActionResponse,
        BackupStateResponse,
        BackupSnapshotResponse,
        SnapshotCompressionResponse,
        BackupDiffResponse,
        BackupDiffSkipReasonResponse,
        BackupsErrorResponse
    )),
    modifiers(&BearerSecurity),
    tags((
        name = "Backups",
        description = "List, download, restore and remove immutable file snapshots"
    ))
)]
struct BackupsApiDoc;

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
                            "JWT returned by POST /auth/login. An active workgroup session is required."
                                .to_owned(),
                        ))
                        .build(),
                ),
            );
        }
    }
}

pub fn base_document() -> utoipa::openapi::OpenApi {
    BackupsApiDoc::openapi()
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
        backups::{
            application::lifecycle::BackupLifecycleService, presentation::state::BackupsState,
        },
    };

    #[derive(Clone)]
    struct DocumentationState;

    impl JwtExtractorState for DocumentationState {
        fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
            panic!("documentation generation does not resolve authentication")
        }
    }

    impl BackupsState for DocumentationState {
        fn backup_lifecycle_service(&self) -> Arc<BackupLifecycleService> {
            panic!("documentation generation does not resolve application services")
        }
    }

    #[test]
    fn documents_all_backup_routes_as_openapi_3_1() {
        let document = OpenApiRouter::<DocumentationState>::with_openapi(base_document())
            .nest("/backups", super::super::routes::router())
            .into_openapi();
        let specification = serde_json::to_value(document).unwrap();

        assert_eq!(specification["openapi"], "3.1.0");
        assert!(specification["paths"]["/backups/list"]["get"].is_object());
        assert!(specification["paths"]["/backups/backup/{backup_id}"]["get"].is_object());
        assert!(specification["paths"]["/backups/backup/{backup_id}"]["delete"].is_object());
        assert!(specification["paths"]["/backups/restore/{backup_id}"]["post"].is_object());
        assert_eq!(
            specification["components"]["securitySchemes"][BEARER_AUTH_SCHEME]["scheme"],
            "bearer"
        );
        assert!(specification["components"]["schemas"]["BackupDiffResponse"].is_object());
    }
}
