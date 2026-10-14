use axum::{Json, Router, routing::get};
use utoipa::{Modify, OpenApi};

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};

use super::dto::{LoginRequest, LoginResponse, SessionResponse, SessionUserResponse};

const BEARER_AUTH_SCHEME: &str = "bearerAuth";

#[derive(OpenApi)]
#[openapi(
    components(schemas(
        LoginRequest,
        LoginResponse,
        SessionResponse,
        SessionUserResponse
    )),
    modifiers(&BearerSecurity),
    tags(
        (name = "Authentication", description = "Login and session validation")
    )
)]
struct AuthApiDoc;

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
                            "JWT returned by POST /auth/login. Send it as `Authorization: Bearer <token>`."
                                .to_owned(),
                        ))
                        .build(),
                ),
            );
        }
    }
}

pub fn base_document() -> utoipa::openapi::OpenApi {
    AuthApiDoc::openapi()
}

pub fn router<S>(document: utoipa::openapi::OpenApi) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route(
        "/openapi.json",
        get(move || async move { Json(document.clone()) }),
    )
}

#[cfg(test)]
mod tests {
    use axum::{
        body::to_bytes,
        http::{Request, StatusCode},
    };
    use serde_json::Value;
    use std::sync::Arc;
    use tower::ServiceExt;
    use utoipa_axum::router::OpenApiRouter;

    use crate::auth::{
        application::{authenticate_jwt::AuthenticateBearerToken, login::Login},
        presentation::{extractors::JwtExtractorState, state::LoginState},
    };

    use super::*;

    #[derive(Clone)]
    struct DocumentationState;

    impl LoginState for DocumentationState {
        fn login_service(&self) -> Arc<dyn Login> {
            panic!("documentation generation does not resolve application services")
        }
    }

    impl JwtExtractorState for DocumentationState {
        fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
            panic!("documentation generation does not resolve application services")
        }
    }

    fn document() -> utoipa::openapi::OpenApi {
        OpenApiRouter::<DocumentationState>::with_openapi(base_document())
            .nest("/auth", super::super::routes::router())
            .into_openapi()
    }

    #[test]
    fn documents_all_auth_routes_as_openapi_3_1() {
        let specification = serde_json::to_value(document()).unwrap();

        assert_eq!(specification["openapi"], "3.1.0");
        assert!(specification["paths"]["/auth/login"]["post"].is_object());
        assert!(specification["paths"]["/auth/session"]["get"].is_object());
        assert_eq!(
            specification["paths"]["/auth/session"]["get"]["security"][0][BEARER_AUTH_SCHEME],
            serde_json::json!([])
        );
        assert_eq!(
            specification["components"]["securitySchemes"][BEARER_AUTH_SCHEME]["scheme"],
            "bearer"
        );
        assert_eq!(
            specification["components"]["securitySchemes"][BEARER_AUTH_SCHEME]["bearerFormat"],
            "JWT"
        );
    }

    #[tokio::test]
    async fn serves_generated_document_as_json() {
        let response = router::<()>(document())
            .oneshot(
                Request::builder()
                    .uri("/openapi.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            "application/json"
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let specification: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(specification["openapi"], "3.1.0");
    }
}
