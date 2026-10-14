use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{
    application::login::LoginResult,
    domain::models::{AuthenticatedPrincipal, AuthenticatedUser},
};

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub access_token: String,
    pub token_type: String,
    /// RFC 3339 UTC timestamp.
    pub expires_at: String,
    pub user: SessionUserResponse,
}

impl From<LoginResult> for LoginResponse {
    fn from(result: LoginResult) -> Self {
        Self {
            access_token: result.access_token,
            token_type: "Bearer".into(),
            expires_at: result.expires_at.to_rfc3339(),
            user: result.user.into(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub user: SessionUserResponse,
    /// RFC 3339 UTC timestamp.
    pub expires_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionUserResponse {
    pub id: i64,
    pub username: String,
    pub main_group: i32,
    pub permissions: Vec<i32>,
    pub avatar: Option<String>,
}

impl From<AuthenticatedPrincipal> for SessionResponse {
    fn from(principal: AuthenticatedPrincipal) -> Self {
        Self {
            user: principal.user.into(),
            expires_at: principal.token_expires_at.to_rfc3339(),
        }
    }
}

impl From<AuthenticatedUser> for SessionUserResponse {
    fn from(user: AuthenticatedUser) -> Self {
        Self {
            id: user.id,
            username: user.username,
            main_group: user.main_group.as_i32(),
            permissions: user.permissions.into_iter().map(Into::into).collect(),
            avatar: user.avatar,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn deserializes_login_request() {
        let request: LoginRequest = serde_json::from_value(json!({
            "email": "neo@example.com",
            "password": "secret"
        }))
        .unwrap();

        assert_eq!(request.email, "neo@example.com");
        assert_eq!(request.password, "secret");
    }

    #[test]
    fn serializes_safe_login_response_in_camel_case() {
        let response = LoginResponse {
            access_token: "signed.jwt".into(),
            token_type: "Bearer".into(),
            expires_at: "2026-10-14T15:30:00+00:00".into(),
            user: SessionUserResponse {
                id: 42,
                username: "neo".into(),
                main_group: 11,
                permissions: vec![9, 11],
                avatar: None,
            },
        };

        let value = serde_json::to_value(response).unwrap();

        assert_eq!(value["accessToken"], "signed.jwt");
        assert_eq!(value["tokenType"], "Bearer");
        assert_eq!(value["expiresAt"], "2026-10-14T15:30:00+00:00");
        assert_eq!(value["user"]["id"], 42);
        assert_eq!(value["user"]["mainGroup"], 11);
        assert_eq!(value["user"]["permissions"], json!([9, 11]));
        assert!(value.get("password").is_none());
        assert!(value.get("sessionId").is_none());
    }
}
