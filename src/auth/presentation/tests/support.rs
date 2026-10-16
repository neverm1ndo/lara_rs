use std::{
    collections::HashMap,
    convert::Infallible,
    future,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        Method, Request, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    response::Response,
};
use chrono::{Duration, Utc};
use md5::{Digest, Md5};
use serde_json::Value;
use tower::ServiceExt;

use crate::{
    auth::{
        application::{
            authenticate_jwt::{
                AuthenticateBearerToken, AuthenticatedUserRepository, AuthenticationError,
                JwtAuthenticationService, JwtVerifier,
            },
            login::{Login, LoginError, LoginResult, LoginService},
            login_user_repository::{LoginUser, LoginUserRepository},
            session_id_generator::SessionIdGenerator,
            session_repository::SessionRepository,
        },
        domain::models::{
            AuthenticatedPrincipal, AuthenticatedUser, JwtClaims, Session, SessionId, UserId,
        },
        infrastructure::{
            jwt::{Hs256JwtIssuer, Hs256JwtVerifier},
            legacy_md5_verifier::LegacyMd5Verifier,
        },
        presentation::router,
    },
    shared::user_role::UserRole,
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

struct LoginStub(Result<LoginResult, LoginError>);

impl Login for LoginStub {
    fn login<'a>(
        &'a self,
        _email: &'a str,
        _password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<LoginResult, LoginError>> + Send + 'a>> {
        Box::pin(future::ready(self.0.clone()))
    }
}

#[derive(Clone)]
struct TestState {
    jwt_authenticator: Arc<dyn AuthenticateBearerToken>,
    login_service: Arc<dyn Login>,
}

// Fully qualified trait paths keep rust-analyzer's test-module resolution
// unambiguous after the fixtures are split across files.
impl crate::auth::presentation::extractors::JwtExtractorState for TestState {
    fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
        Arc::clone(&self.jwt_authenticator)
    }
}

impl crate::auth::presentation::state::LoginState for TestState {
    fn login_service(&self) -> Arc<dyn Login> {
        Arc::clone(&self.login_service)
    }
}

fn authenticated_user() -> AuthenticatedUser {
    AuthenticatedUser {
        id: 42,
        username: "neo".into(),
        main_group: UserRole::Challenger,
        permissions: vec![UserRole::Challenger, UserRole::Admin],
        avatar: None,
    }
}

pub(super) fn stub_principal() -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        user: authenticated_user(),
        session_id: SessionId::new("do-not-expose-this").unwrap(),
        token_expires_at: Utc::now() + Duration::minutes(5),
    }
}

pub(super) fn stub_login_result() -> LoginResult {
    LoginResult {
        access_token: "signed.jwt".into(),
        expires_at: Utc::now() + Duration::hours(1),
        user: authenticated_user(),
    }
}

fn test_state(
    authenticator: Arc<dyn AuthenticateBearerToken>,
    login_service: Arc<dyn Login>,
) -> TestState {
    TestState {
        jwt_authenticator: authenticator,
        login_service,
    }
}

pub(super) async fn request_with_authenticator(
    authenticator: Arc<dyn AuthenticateBearerToken>,
    with_token: bool,
) -> Response {
    let state = test_state(authenticator, Arc::new(LoginStub(Ok(stub_login_result()))));
    let app = Router::new()
        .nest("/auth", router::<TestState>().into())
        .with_state(state);
    let mut request = Request::builder().uri("/auth/session");
    if with_token {
        request = request.header(AUTHORIZATION, "Bearer signed.jwt");
    }

    app.oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

pub(super) async fn session_request(
    result: Result<AuthenticatedPrincipal, AuthenticationError>,
    with_token: bool,
) -> Response {
    request_with_authenticator(Arc::new(Authenticator(result)), with_token).await
}

pub(super) async fn login_request(result: Result<LoginResult, LoginError>, body: &str) -> Response {
    let state = test_state(
        Arc::new(Authenticator(Ok(stub_principal()))),
        Arc::new(LoginStub(result)),
    );
    let app = Router::new()
        .nest("/auth", router::<TestState>().into())
        .with_state(state);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/login")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();

    app.oneshot(request).await.unwrap()
}

struct ClaimsVerifier(JwtClaims);

impl JwtVerifier for ClaimsVerifier {
    type Error = Infallible;

    fn verify(&self, _token: &str) -> Result<JwtClaims, Self::Error> {
        Ok(self.0.clone())
    }
}

struct SessionStore(Session);

impl SessionRepository for SessionStore {
    type Error = Infallible;

    fn create(&self, _session: &Session) -> impl Future<Output = Result<(), Self::Error>> + Send {
        future::ready(Ok(()))
    }

    fn find_by_id(
        &self,
        _session_id: &SessionId,
    ) -> impl Future<Output = Result<Option<Session>, Self::Error>> + Send {
        future::ready(Ok(Some(self.0.clone())))
    }
}

struct UserStore(AuthenticatedUser);

impl AuthenticatedUserRepository for UserStore {
    type Error = Infallible;

    fn find_by_id(
        &self,
        _user_id: i32,
    ) -> impl Future<Output = Result<Option<AuthenticatedUser>, Self::Error>> + Send {
        future::ready(Ok(Some(self.0.clone())))
    }
}

pub(super) fn service_with_session(session: Session) -> Arc<dyn AuthenticateBearerToken> {
    let now = Utc::now().timestamp();
    let claims = JwtClaims {
        sub: UserId::new(42).unwrap(),
        sid: SessionId::new("session-1").unwrap(),
        exp: now + 60,
        iat: now,
        iss: "lara".into(),
        aud: "lara-api".into(),
    };

    Arc::new(JwtAuthenticationService::new(
        ClaimsVerifier(claims),
        SessionStore(session),
        UserStore(authenticated_user()),
    ))
}

pub(super) fn active_session() -> Session {
    Session {
        id: SessionId::new("session-1").unwrap(),
        user_id: UserId::new(42).unwrap(),
        expires_at: Utc::now() + Duration::minutes(5),
        revoked_at: None,
    }
}

#[derive(Clone, Default)]
pub(super) struct SharedSessions(Arc<Mutex<HashMap<String, Session>>>);

impl SharedSessions {
    pub(super) fn update(&self, update: impl FnOnce(&mut Session)) {
        let mut sessions = self.0.lock().unwrap();
        let session = sessions.get_mut("session-1").unwrap();
        update(session);
    }
}

impl SessionRepository for SharedSessions {
    type Error = Infallible;

    fn create(&self, session: &Session) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.0
            .lock()
            .unwrap()
            .insert(session.id.as_str().to_owned(), session.clone());
        future::ready(Ok(()))
    }

    fn find_by_id(
        &self,
        session_id: &SessionId,
    ) -> impl Future<Output = Result<Option<Session>, Self::Error>> + Send {
        let session = self.0.lock().unwrap().get(session_id.as_str()).cloned();
        future::ready(Ok(session))
    }
}

#[derive(Clone)]
pub(super) struct SharedUsers(Arc<Mutex<LoginUser>>);

impl SharedUsers {
    pub(super) fn remove_work_groups(&self) {
        self.0.lock().unwrap().permissions.clear();
    }
}

impl LoginUserRepository for SharedUsers {
    type Error = Infallible;

    fn find_by_email(
        &self,
        _email: &str,
    ) -> impl Future<Output = Result<Option<LoginUser>, Self::Error>> + Send {
        future::ready(Ok(Some(self.0.lock().unwrap().clone())))
    }
}

impl AuthenticatedUserRepository for SharedUsers {
    type Error = Infallible;

    fn find_by_id(
        &self,
        user_id: i32,
    ) -> impl Future<Output = Result<Option<AuthenticatedUser>, Self::Error>> + Send {
        let login_user = self.0.lock().unwrap().clone();
        let user = (login_user.id.get() == i64::from(user_id))
            .then(|| login_user.into_authenticated_user());
        future::ready(Ok(user))
    }
}

struct FixedSessionIds;

impl SessionIdGenerator for FixedSessionIds {
    fn generate(&self) -> SessionId {
        SessionId::new("session-1").unwrap()
    }
}

fn legacy_hash(salt: &str, password: &str) -> String {
    let digest = Md5::digest(format!("{salt}{password}").as_bytes());
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{salt}{digest}")
}

pub(super) fn integrated_app() -> (Router, SharedSessions, SharedUsers) {
    const SECRET: &str = "integration-test-secret";
    const ISSUER: &str = "lara";
    const AUDIENCE: &str = "lara-api";

    let sessions = SharedSessions::default();
    let users = SharedUsers(Arc::new(Mutex::new(LoginUser {
        id: UserId::new(42).unwrap(),
        username: "neo".into(),
        main_group: UserRole::Admin,
        permissions: vec![UserRole::Challenger, UserRole::Admin],
        avatar: None,
        password_hash: legacy_hash("random-salt", "correct"),
    })));
    let login = LoginService::new(
        LegacyMd5Verifier,
        users.clone(),
        sessions.clone(),
        FixedSessionIds,
        Hs256JwtIssuer::new(SECRET, ISSUER, AUDIENCE).unwrap(),
        ISSUER,
        AUDIENCE,
        3_600,
    )
    .unwrap();
    let authenticator = JwtAuthenticationService::new(
        Hs256JwtVerifier::new(SECRET, ISSUER, AUDIENCE).unwrap(),
        sessions.clone(),
        users.clone(),
    );
    let state = test_state(Arc::new(authenticator), Arc::new(login));
    let app = Router::new()
        .nest("/auth", router::<TestState>().into())
        .with_state(state);

    (app, sessions, users)
}

pub(super) async fn login_through_http(app: &Router) -> String {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/login")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"email":"neo@example.com","password":"correct"}"#,
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    json["accessToken"].as_str().unwrap().to_owned()
}

pub(super) async fn validate_session_through_http(app: Router, token: &str) -> Response {
    let request = Request::builder()
        .uri("/auth/session")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    app.oneshot(request).await.unwrap()
}
