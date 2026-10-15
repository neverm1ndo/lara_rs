use std::{future, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::AUTHORIZATION},
};
use chrono::{Duration, Utc};
use serde_json::Value;
use tower::ServiceExt;

use crate::{
    auth::{
        application::authenticate_jwt::{AuthenticateBearerToken, AuthenticationError},
        domain::models::{AuthenticatedPrincipal, AuthenticatedUser, SessionId},
        presentation::extractors::JwtExtractorState,
    },
    configuration::{
        application::file_service::{
            ConfigurationFileService, ConfigurationFileServiceError, ConfigurationRequestContext,
            ConfigurationServiceFuture, ConfigurationTextFile, ConfigurationTreeEntry,
            ConfigurationTreeEntryKind,
        },
        domain::ConfigurationFileChanged,
        presentation::{
            authorization::ConfigurationAuthorizationState, routes::router,
            state::ConfigurationState,
        },
    },
    shared::{file_storage::path::RelativeStoragePath, user_role::UserRole},
};

struct Authenticator(AuthenticatedPrincipal);

impl AuthenticateBearerToken for Authenticator {
    fn authenticate<'a>(
        &'a self,
        _token: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<AuthenticatedPrincipal, AuthenticationError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(future::ready(Ok(self.0.clone())))
    }
}

struct StubService;

impl ConfigurationFileService for StubService {
    fn tree<'a>(
        &'a self,
        _context: ConfigurationRequestContext,
    ) -> ConfigurationServiceFuture<'a, Vec<ConfigurationTreeEntry>> {
        Box::pin(future::ready(Ok(vec![ConfigurationTreeEntry {
            path: RelativeStoragePath::new("server.cfg").unwrap(),
            name: "server.cfg".into(),
            kind: ConfigurationTreeEntryKind::Text,
            size: Some(15),
            modified_at: None,
            children: vec![],
        }])))
    }

    fn open_text<'a>(
        &'a self,
        _context: ConfigurationRequestContext,
        _path: RelativeStoragePath,
    ) -> ConfigurationServiceFuture<'a, ConfigurationTextFile> {
        Box::pin(future::ready(Ok(ConfigurationTextFile {
            reader: Box::pin(std::io::Cursor::new(b"hostname open.mp".to_vec())),
            content_length: Some(16),
            file_name: "server.cfg".into(),
        })))
    }

    fn create<'a>(
        &'a self,
        _context: ConfigurationRequestContext,
        _path: RelativeStoragePath,
        _content: String,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged> {
        unavailable()
    }

    fn overwrite<'a>(
        &'a self,
        _context: ConfigurationRequestContext,
        _path: RelativeStoragePath,
        _content: String,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged> {
        unavailable()
    }

    fn delete<'a>(
        &'a self,
        _context: ConfigurationRequestContext,
        _path: RelativeStoragePath,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged> {
        unavailable()
    }

    fn rename<'a>(
        &'a self,
        _context: ConfigurationRequestContext,
        _source: RelativeStoragePath,
        _destination: RelativeStoragePath,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged> {
        unavailable()
    }
}

fn unavailable<'a, T: Send + 'a>() -> ConfigurationServiceFuture<'a, T> {
    Box::pin(future::ready(Err(
        ConfigurationFileServiceError::Unavailable,
    )))
}

#[derive(Clone)]
struct TestState {
    authenticator: Arc<dyn AuthenticateBearerToken>,
    service: Arc<dyn ConfigurationFileService>,
    configurator_directory: RelativeStoragePath,
}

impl JwtExtractorState for TestState {
    fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
        Arc::clone(&self.authenticator)
    }
}

impl ConfigurationAuthorizationState for TestState {
    fn configurator_directory(&self) -> &RelativeStoragePath {
        &self.configurator_directory
    }
}

impl ConfigurationState for TestState {
    fn configuration_file_service(&self) -> Arc<dyn ConfigurationFileService> {
        Arc::clone(&self.service)
    }
}

fn principal(role: UserRole) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        user: AuthenticatedUser {
            id: 42,
            username: "neo".into(),
            main_group: role,
            permissions: vec![],
            avatar: None,
        },
        session_id: SessionId::new("session-1").unwrap(),
        token_expires_at: Utc::now() + Duration::minutes(5),
    }
}

fn app(role: UserRole) -> axum::Router {
    let state = TestState {
        authenticator: Arc::new(Authenticator(principal(role))),
        service: Arc::new(StubService),
        configurator_directory: RelativeStoragePath::new("scriptfiles/config").unwrap(),
    };
    router::<TestState>().with_state(state).split_for_parts().0
}

fn authorized_request(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(AUTHORIZATION, "Bearer signed.jwt")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn tree_endpoint_returns_the_role_scoped_tree() {
    let response = app(UserRole::DEVELOPER)
        .oneshot(authorized_request("/tree"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["entries"][0]["path"], "server.cfg");
    assert_eq!(value["entries"][0]["kind"], "text");
}

#[tokio::test]
async fn read_endpoint_streams_utf8_text_with_download_metadata() {
    let response = app(UserRole::CONFIGURATOR)
        .oneshot(authorized_request("/files?path=server.cfg"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "text/plain; charset=utf-8"
    );
    assert_eq!(response.headers()["content-length"], "16");
    assert!(
        response.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .contains("server.cfg")
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"hostname open.mp");
}

#[tokio::test]
async fn endpoints_reject_users_outside_the_two_allowed_roles() {
    let response = app(UserRole::ADMIN)
        .oneshot(authorized_request("/tree"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn read_endpoint_rejects_traversal_before_calling_the_service() {
    let response = app(UserRole::DEVELOPER)
        .oneshot(authorized_request("/files?path=../server.cfg"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
