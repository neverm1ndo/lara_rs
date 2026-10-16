use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use super::dto::{UserErrorResponse, UserResponse};

const BEARER_AUTH_SCHEME: &str = "bearerAuth";

#[derive(OpenApi)]
#[openapi(
    components(schemas(UserResponse, UserErrorResponse)),
    modifiers(&BearerSecurity),
    tags((
        name = "Users",
        description = "Read workspace-user profiles. Available to every authenticated workspace role."
    ))
)]
struct UserApiDoc;

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
                            "JWT returned by POST /auth/login. Any current workspace role is allowed."
                                .to_owned(),
                        ))
                        .build(),
                ),
            );
        }
    }
}

pub fn base_document() -> utoipa::openapi::OpenApi {
    UserApiDoc::openapi()
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
        user::{application::get_user::GetUser, presentation::state::UserState},
    };

    #[derive(Clone)]
    struct DocumentationState;

    impl JwtExtractorState for DocumentationState {
        fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
            panic!("documentation generation does not resolve authentication")
        }
    }

    impl UserState for DocumentationState {
        fn get_user_service(&self) -> Arc<dyn GetUser> {
            panic!("documentation generation does not resolve application services")
        }
    }

    fn document() -> utoipa::openapi::OpenApi {
        OpenApiRouter::<DocumentationState>::with_openapi(base_document())
            .nest("/user", super::super::routes::router())
            .into_openapi()
    }

    #[test]
    fn documents_user_route_as_protected_openapi_3_1_operation() {
        let specification = serde_json::to_value(document()).unwrap();
        let operation = &specification["paths"]["/user/{id}"]["get"];

        assert_eq!(specification["openapi"], "3.1.0");
        assert!(operation.is_object());
        assert_eq!(
            operation["security"][0][BEARER_AUTH_SCHEME],
            serde_json::json!([])
        );
        assert_eq!(
            specification["components"]["securitySchemes"][BEARER_AUTH_SCHEME]["scheme"],
            "bearer"
        );
        assert!(specification["components"]["schemas"]["UserResponse"].is_object());
        assert!(specification["components"]["schemas"]["UserErrorResponse"].is_object());
    }

    #[test]
    fn public_schema_does_not_expose_credentials_or_session_data() {
        let specification = serde_json::to_value(document()).unwrap();
        let properties = &specification["components"]["schemas"]["UserResponse"]["properties"];

        for forbidden in ["email", "password", "passwordHash", "sessionId"] {
            assert!(properties.get(forbidden).is_none(), "exposed {forbidden}");
        }
    }
}
