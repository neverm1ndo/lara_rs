use axum::{body::to_bytes, http::StatusCode};
use chrono::{Duration, Utc};
use serde_json::Value;

use crate::auth::application::login::LoginError;

use super::support::{
    integrated_app, login_request, login_through_http, validate_session_through_http,
};

#[tokio::test]
async fn login_returns_token_and_safe_user() {
    let response = login_request(
        Ok(super::support::stub_login_result()),
        r#"{"email":"neo@example.com","password":"secret"}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["accessToken"], "signed.jwt");
    assert_eq!(json["tokenType"], "Bearer");
    assert!(json["expiresAt"].as_str().is_some());
    assert_eq!(json["user"]["id"], 42);
    assert_eq!(json["user"]["permissions"], serde_json::json!([9, 11]));
    assert!(json.get("password").is_none());
    assert!(json.get("sessionId").is_none());
}

#[tokio::test]
async fn login_maps_application_errors_to_http_statuses() {
    let unauthorized = login_request(
        Err(LoginError::InvalidCredentials),
        r#"{"email":"neo@example.com","password":"wrong"}"#,
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let unavailable = login_request(
        Err(LoginError::Unavailable),
        r#"{"email":"neo@example.com","password":"secret"}"#,
    )
    .await;
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn login_rejects_malformed_json_as_bad_request() {
    let response = login_request(Ok(super::support::stub_login_result()), r#"{"email":42}"#).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn issued_token_validates_the_created_session_end_to_end() {
    let (app, _sessions, _users) = integrated_app();
    let token = login_through_http(&app).await;

    let response = validate_session_through_http(app, &token).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["user"]["id"], 42);
    assert_eq!(json["user"]["username"], "neo");
    assert_eq!(json["user"]["mainGroup"], 11);
    assert_eq!(json["user"]["permissions"], serde_json::json!([9, 11]));
    assert!(json.get("sessionId").is_none());
}

#[tokio::test]
async fn issued_token_is_rejected_after_session_revocation_or_expiration() {
    let (revoked_app, revoked_sessions, _users) = integrated_app();
    let revoked_token = login_through_http(&revoked_app).await;
    revoked_sessions.update(|session| session.revoked_at = Some(Utc::now()));

    let response = validate_session_through_http(revoked_app, &revoked_token).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let (expired_app, expired_sessions, _users) = integrated_app();
    let expired_token = login_through_http(&expired_app).await;
    expired_sessions.update(|session| session.expires_at = Utc::now() - Duration::seconds(1));

    let response = validate_session_through_http(expired_app, &expired_token).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn issued_token_is_rejected_after_user_loses_work_group() {
    let (app, _sessions, users) = integrated_app();
    let token = login_through_http(&app).await;
    users.remove_from_workspace();

    let response = validate_session_through_http(app, &token).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
