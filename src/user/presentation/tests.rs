use std::{
    future::{self, Future},
    pin::Pin,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::AUTHORIZATION},
    response::Response,
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
    shared::user_role::UserRole,
    user::{
        application::get_user::{GetUser, GetUserError},
        domain::profile::{UserId, UserProfile},
        presentation::{router, state::UserState},
    },
};

struct Authenticator(Result<AuthenticatedPrincipal, AuthenticationError>);

impl AuthenticateBearerToken for Authenticator {
    fn authenticate<'a>(
        &'a self,
        _token: &'a str,
    ) -> Pin<
        Box<dyn Future<Output = Result<AuthenticatedPrincipal, AuthenticationError>> + Send + 'a>,
    > {
        Box::pin(future::ready(self.0.clone()))
    }
}

struct RecordingGetUser {
    result: Result<UserProfile, GetUserError>,
    requested_ids: Arc<Mutex<Vec<UserId>>>,
}

impl GetUser for RecordingGetUser {
    fn get_user(
        &self,
        id: UserId,
    ) -> Pin<Box<dyn Future<Output = Result<UserProfile, GetUserError>> + Send + '_>> {
        self.requested_ids.lock().unwrap().push(id);
        Box::pin(future::ready(self.result.clone()))
    }
}

#[derive(Clone)]
struct TestState {
    authenticator: Arc<dyn AuthenticateBearerToken>,
    get_user: Arc<dyn GetUser>,
}

impl JwtExtractorState for TestState {
    fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
        Arc::clone(&self.authenticator)
    }
}

impl UserState for TestState {
    fn get_user_service(&self) -> Arc<dyn GetUser> {
        Arc::clone(&self.get_user)
    }
}

fn principal(role: UserRole) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        user: AuthenticatedUser {
            id: 7,
            username: "requester".into(),
            main_group: role,
            permissions: vec![role],
            avatar: None,
        },
        session_id: SessionId::new("session-1").unwrap(),
        token_expires_at: Utc::now() + Duration::minutes(5),
    }
}

fn profile() -> UserProfile {
    UserProfile::new(
        UserId::new(42).unwrap(),
        "neo",
        Some("neo.png".into()),
        UserRole::ADMIN,
        vec![UserRole::CHALLENGER, UserRole::ADMIN],
    )
    .unwrap()
}

fn test_app(
    authentication: Result<AuthenticatedPrincipal, AuthenticationError>,
    result: Result<UserProfile, GetUserError>,
) -> (Router, Arc<Mutex<Vec<UserId>>>) {
    let requested_ids = Arc::new(Mutex::new(Vec::new()));
    let state = TestState {
        authenticator: Arc::new(Authenticator(authentication)),
        get_user: Arc::new(RecordingGetUser {
            result,
            requested_ids: Arc::clone(&requested_ids),
        }),
    };
    let app = Router::new()
        .nest("/user", router::<TestState>().into())
        .with_state(state);

    (app, requested_ids)
}

fn request(uri: &str, with_token: bool) -> Request<Body> {
    let mut request = Request::builder().uri(uri);
    if with_token {
        request = request.header(AUTHORIZATION, "Bearer signed.jwt");
    }
    request.body(Body::empty()).unwrap()
}

async fn json_body(response: Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn every_workspace_role_can_read_a_safe_user_profile() {
    for role in [
        UserRole::CHALLENGER,
        UserRole::DEVELOPER,
        UserRole::ADMIN,
        UserRole::MAPPER,
        UserRole::CONFIGURATOR,
        UserRole::BACKUPER,
    ] {
        let (app, requested_ids) = test_app(Ok(principal(role)), Ok(profile()));
        let response = app.oneshot(request("/user/42", true)).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK, "role: {role:?}");
        let body = json_body(response).await;
        assert_eq!(body["id"], 42);
        assert_eq!(body["username"], "neo");
        assert_eq!(body["avatar"], "neo.png");
        assert_eq!(body["mainGroup"], 11);
        assert_eq!(body["permissions"], serde_json::json!([9, 11]));
        for forbidden in ["email", "password", "passwordHash", "sessionId"] {
            assert!(body.get(forbidden).is_none(), "exposed {forbidden}");
        }
        assert_eq!(
            requested_ids.lock().unwrap().as_slice(),
            &[UserId::new(42).unwrap()]
        );
    }
}

#[tokio::test]
async fn endpoint_requires_a_valid_authenticated_session() {
    let (app, requested_ids) = test_app(Ok(principal(UserRole::CHALLENGER)), Ok(profile()));
    let missing = app.oneshot(request("/user/42", false)).await.unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert!(requested_ids.lock().unwrap().is_empty());

    for (error, expected) in [
        (AuthenticationError::Unauthorized, StatusCode::UNAUTHORIZED),
        (
            AuthenticationError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        let (app, requested_ids) = test_app(Err(error), Ok(profile()));
        let response = app.oneshot(request("/user/42", true)).await.unwrap();

        assert_eq!(response.status(), expected);
        assert!(requested_ids.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn malformed_non_positive_ids_are_rejected_before_the_service() {
    for uri in ["/user/not-a-number", "/user/0", "/user/-1"] {
        let (app, requested_ids) = test_app(Ok(principal(UserRole::ADMIN)), Ok(profile()));
        let response = app.oneshot(request(uri, true)).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "uri: {uri}");
        assert_eq!(json_body(response).await["code"], "INVALID_USER_ID");
        assert!(requested_ids.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn application_failures_are_mapped_to_stable_http_errors() {
    for (error, status, code) in [
        (
            GetUserError::NotFound,
            StatusCode::NOT_FOUND,
            "USER_NOT_FOUND",
        ),
        (
            GetUserError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
        ),
    ] {
        let (app, requested_ids) = test_app(Ok(principal(UserRole::MAPPER)), Err(error));
        let response = app.oneshot(request("/user/42", true)).await.unwrap();

        assert_eq!(response.status(), status);
        assert_eq!(json_body(response).await["code"], code);
        assert_eq!(
            requested_ids.lock().unwrap().as_slice(),
            &[UserId::new(42).unwrap()]
        );
    }
}
