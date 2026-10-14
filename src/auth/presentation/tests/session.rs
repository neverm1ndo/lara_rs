use axum::{body::to_bytes, http::StatusCode};
use chrono::{Duration, Utc};
use serde_json::Value;

use crate::auth::application::authenticate_jwt::AuthenticationError;

use super::support::{
    active_session, request_with_authenticator, service_with_session, session_request,
    stub_principal,
};

#[tokio::test]
async fn returns_safe_session_response() {
    let response = session_request(Ok(stub_principal()), true).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["user"]["id"], 42);
    assert_eq!(json["user"]["username"], "neo");
    assert_eq!(json["user"]["mainGroup"], 9);
    assert_eq!(json["user"]["permissions"], serde_json::json!([9, 11]));
    assert!(json["expiresAt"].as_str().is_some());
    assert!(json.get("sessionId").is_none());
}

#[tokio::test]
async fn returns_unauthorized_without_a_token() {
    let response = session_request(Ok(stub_principal()), false).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn returns_service_unavailable_for_dependency_failure() {
    let response = session_request(Err(AuthenticationError::Unavailable), true).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn returns_unauthorized_for_revoked_session_through_real_service() {
    let mut session = active_session();
    session.revoked_at = Some(Utc::now());

    let response = request_with_authenticator(service_with_session(session), true).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn returns_unauthorized_for_expired_session_through_real_service() {
    let mut session = active_session();
    session.expires_at = Utc::now() - Duration::seconds(1);

    let response = request_with_authenticator(service_with_session(session), true).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
