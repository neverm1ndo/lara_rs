use std::{future, future::Future, pin::Pin, sync::Arc};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        Method, Request, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
};
use chrono::{Duration, Utc};
use serde_json::Value;
use tower::ServiceExt;

use crate::auth::{
    application::{
        authenticate_jwt::{AuthenticateBearerToken, AuthenticationError},
        mfa::{
            login::{MfaChallengeResult, MfaLogin, MfaLoginError, MfaLoginProof, MfaLoginResult},
            management::{
                ManageMfa, MfaActivation, MfaManagementError, MfaProof, MfaStatus, TotpEnrollment,
            },
        },
    },
    domain::{
        mfa::{MfaChallengeToken, MfaEnrollmentId, RecoveryCode, TotpCode},
        models::{AuthenticatedPrincipal, UserId},
    },
    presentation::{extractors::JwtExtractorState, mfa_router, state::MfaState},
};

use super::support::{stub_login_result, stub_principal};

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

struct LoginStub;

impl MfaLogin for LoginStub {
    fn begin<'a>(
        &'a self,
        _email: &'a str,
        _password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<MfaLoginResult, MfaLoginError>> + Send + 'a>> {
        Box::pin(future::ready(Ok(MfaLoginResult::MfaRequired(
            MfaChallengeResult {
                challenge_token: MfaChallengeToken::new("opaque-challenge").unwrap(),
                expires_at: Utc::now() + Duration::minutes(5),
            },
        ))))
    }

    fn complete<'a>(
        &'a self,
        _challenge_token: &'a MfaChallengeToken,
        _proof: &'a MfaLoginProof,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<crate::auth::application::login::LoginResult, MfaLoginError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(future::ready(Ok(stub_login_result())))
    }
}

struct ManagementStub;

impl ManageMfa for ManagementStub {
    fn status<'a>(
        &'a self,
        _user_id: UserId,
    ) -> Pin<Box<dyn Future<Output = Result<MfaStatus, MfaManagementError>> + Send + 'a>> {
        Box::pin(future::ready(Ok(MfaStatus::Enabled)))
    }

    fn begin_enrollment<'a>(
        &'a self,
        _user_id: UserId,
        _account_name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<TotpEnrollment, MfaManagementError>> + Send + 'a>> {
        Box::pin(future::ready(Err(MfaManagementError::NotFound)))
    }

    fn confirm_enrollment<'a>(
        &'a self,
        _user_id: UserId,
        _enrollment_id: MfaEnrollmentId,
        _code: &'a TotpCode,
    ) -> Pin<Box<dyn Future<Output = Result<MfaActivation, MfaManagementError>> + Send + 'a>> {
        Box::pin(future::ready(Err(MfaManagementError::NotFound)))
    }

    fn disable<'a>(
        &'a self,
        _user_id: UserId,
        _proof: MfaProof<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<(), MfaManagementError>> + Send + 'a>> {
        Box::pin(future::ready(Err(MfaManagementError::NotFound)))
    }

    fn regenerate_recovery_codes<'a>(
        &'a self,
        _user_id: UserId,
        _proof: MfaProof<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<RecoveryCode>, MfaManagementError>> + Send + 'a>>
    {
        Box::pin(future::ready(Err(MfaManagementError::NotFound)))
    }
}

#[derive(Clone)]
struct TestState {
    authenticator: Arc<dyn AuthenticateBearerToken>,
    login: Arc<dyn MfaLogin>,
    management: Arc<dyn ManageMfa>,
}

impl JwtExtractorState for TestState {
    fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
        Arc::clone(&self.authenticator)
    }
}

impl MfaState for TestState {
    fn mfa_login_service(&self) -> Arc<dyn MfaLogin> {
        Arc::clone(&self.login)
    }

    fn mfa_management_service(&self) -> Arc<dyn ManageMfa> {
        Arc::clone(&self.management)
    }
}

fn app(authentication: Result<AuthenticatedPrincipal, AuthenticationError>) -> Router {
    let state = TestState {
        authenticator: Arc::new(Authenticator(authentication)),
        login: Arc::new(LoginStub),
        management: Arc::new(ManagementStub),
    };
    Router::new()
        .nest("/auth", mfa_router::<TestState>().into())
        .with_state(state)
}

#[tokio::test]
async fn login_returns_mfa_challenge_instead_of_access_token() {
    let response = app(Ok(stub_principal()))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/auth/login")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"email":"neo@example.com","password":"correct"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["mfaRequired"], true);
    assert_eq!(json["challengeToken"], "opaque-challenge");
    assert!(json.get("accessToken").is_none());
}

#[tokio::test]
async fn protected_mfa_routes_require_bearer_authentication() {
    let response = app(Ok(stub_principal()))
        .oneshot(
            Request::builder()
                .uri("/auth/mfa")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn authenticated_user_can_read_mfa_status() {
    let response = app(Ok(stub_principal()))
        .oneshot(
            Request::builder()
                .uri("/auth/mfa")
                .header(AUTHORIZATION, "Bearer signed.jwt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"status": "enabled", "enabled": true})
    );
}

#[tokio::test]
async fn complete_login_requires_exactly_one_well_formed_proof() {
    for body in [
        r#"{"challengeToken":"opaque-challenge"}"#,
        r#"{"challengeToken":"opaque-challenge","totpCode":"123456","recoveryCode":"code"}"#,
        r#"{"challengeToken":"opaque-challenge","totpCode":"123"}"#,
    ] {
        let response = app(Ok(stub_principal()))
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/auth/login/mfa")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
