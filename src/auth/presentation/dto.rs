use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{
    application::{
        login::LoginResult,
        mfa::{
            login::{MfaChallengeResult, MfaLoginResult},
            management::{MfaActivation, MfaStatus, TotpEnrollment},
        },
    },
    domain::models::{AuthenticatedPrincipal, AuthenticatedUser},
};

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct CompleteMfaLoginRequest {
    pub challenge_token: String,
    pub totp_code: Option<String>,
    pub recovery_code: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(untagged)]
pub enum MfaLoginResponse {
    Authenticated(LoginResponse),
    MfaRequired(MfaChallengeResponse),
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MfaChallengeResponse {
    pub mfa_required: bool,
    pub challenge_token: String,
    /// RFC 3339 UTC timestamp.
    pub expires_at: String,
}

impl From<MfaLoginResult> for MfaLoginResponse {
    fn from(result: MfaLoginResult) -> Self {
        match result {
            MfaLoginResult::Authenticated(login) => Self::Authenticated(login.into()),
            MfaLoginResult::MfaRequired(challenge) => Self::MfaRequired(challenge.into()),
        }
    }
}

impl From<MfaChallengeResult> for MfaChallengeResponse {
    fn from(result: MfaChallengeResult) -> Self {
        Self {
            mfa_required: true,
            challenge_token: result.challenge_token.as_str().to_owned(),
            expires_at: result.expires_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MfaStatusResponse {
    pub status: String,
    pub enabled: bool,
}

impl From<MfaStatus> for MfaStatusResponse {
    fn from(status: MfaStatus) -> Self {
        let (status, enabled) = match status {
            MfaStatus::Disabled => ("disabled", false),
            MfaStatus::EnrollmentPending => ("enrollment_pending", false),
            MfaStatus::Enabled => ("enabled", true),
        };
        Self {
            status: status.into(),
            enabled,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpEnrollmentResponse {
    pub enrollment_id: String,
    pub secret: String,
    pub provisioning_uri: String,
    /// RFC 3339 UTC timestamp.
    pub expires_at: String,
}

impl From<TotpEnrollment> for TotpEnrollmentResponse {
    fn from(enrollment: TotpEnrollment) -> Self {
        Self {
            enrollment_id: enrollment.enrollment_id.to_string(),
            secret: enrollment.secret,
            provisioning_uri: enrollment.provisioning_uri,
            expires_at: enrollment.expires_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct ConfirmTotpEnrollmentRequest {
    pub enrollment_id: String,
    pub code: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct MfaProofRequest {
    pub totp_code: Option<String>,
    pub recovery_code: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCodesResponse {
    pub recovery_codes: Vec<String>,
}

impl From<MfaActivation> for RecoveryCodesResponse {
    fn from(activation: MfaActivation) -> Self {
        Self {
            recovery_codes: activation
                .recovery_codes
                .iter()
                .map(|code| code.as_str().to_owned())
                .collect(),
        }
    }
}

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
