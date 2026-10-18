use axum::{
    Json,
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::auth::{
    application::mfa::{
        login::{MfaLoginError, MfaLoginProof},
        management::{MfaManagementError, MfaProof},
    },
    domain::{
        mfa::{MfaChallengeToken, MfaEnrollmentId, RecoveryCode, TotpCode},
        models::UserId,
    },
};

use super::{
    dto::{
        CompleteMfaLoginRequest, ConfirmTotpEnrollmentRequest, LoginRequest, LoginResponse,
        MfaLoginResponse, MfaProofRequest, MfaStatusResponse, RecoveryCodesResponse,
        TotpEnrollmentResponse,
    },
    extractors::CurrentSession,
    state::{MfaLoginServiceHandle, MfaManagementServiceHandle},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaHttpRejection {
    BadRequest,
    Unauthorized,
    NotFound,
    Conflict,
    Unavailable,
}

impl IntoResponse for MfaHttpRejection {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
        .into_response()
    }
}

impl From<MfaLoginError> for MfaHttpRejection {
    fn from(error: MfaLoginError) -> Self {
        match error {
            MfaLoginError::InvalidCredentials
            | MfaLoginError::InvalidChallenge
            | MfaLoginError::InvalidCode => Self::Unauthorized,
            MfaLoginError::Unavailable => Self::Unavailable,
        }
    }
}

impl From<MfaManagementError> for MfaHttpRejection {
    fn from(error: MfaManagementError) -> Self {
        match error {
            MfaManagementError::NotFound => Self::NotFound,
            MfaManagementError::Conflict => Self::Conflict,
            MfaManagementError::InvalidCode => Self::Unauthorized,
            MfaManagementError::Unavailable => Self::Unavailable,
        }
    }
}

#[utoipa::path(
    post,
    path = "/login",
    tag = "Authentication",
    request_body(content = LoginRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Authenticated, or an MFA challenge is required", body = MfaLoginResponse),
        (status = 400, description = "Malformed request"),
        (status = 401, description = "Invalid credentials"),
        (status = 503, description = "Authentication dependency unavailable")
    )
)]
pub async fn begin_login(
    MfaLoginServiceHandle(service): MfaLoginServiceHandle,
    payload: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Json<MfaLoginResponse>, MfaHttpRejection> {
    let Json(request) = payload.map_err(|_| MfaHttpRejection::BadRequest)?;
    Ok(Json(
        service
            .begin(&request.email, &request.password)
            .await?
            .into(),
    ))
}

#[utoipa::path(
    post,
    path = "/login/mfa",
    tag = "Authentication",
    request_body(content = CompleteMfaLoginRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Second factor accepted and session created", body = LoginResponse),
        (status = 400, description = "Malformed challenge or proof"),
        (status = 401, description = "Invalid, expired, exhausted, or replayed challenge"),
        (status = 503, description = "Authentication dependency unavailable")
    )
)]
pub async fn complete_login(
    MfaLoginServiceHandle(service): MfaLoginServiceHandle,
    payload: Result<Json<CompleteMfaLoginRequest>, JsonRejection>,
) -> Result<Json<LoginResponse>, MfaHttpRejection> {
    let Json(request) = payload.map_err(|_| MfaHttpRejection::BadRequest)?;
    let challenge = MfaChallengeToken::new(request.challenge_token)
        .map_err(|_| MfaHttpRejection::BadRequest)?;
    let proof = login_proof(request.totp_code, request.recovery_code)?;
    Ok(Json(service.complete(&challenge, &proof).await?.into()))
}

#[utoipa::path(
    get,
    path = "/mfa",
    tag = "MFA",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Current MFA state", body = MfaStatusResponse),
        (status = 401, description = "Authentication required"),
        (status = 503, description = "MFA dependency unavailable")
    )
)]
pub async fn status(
    CurrentSession(principal): CurrentSession,
    MfaManagementServiceHandle(service): MfaManagementServiceHandle,
) -> Result<Json<MfaStatusResponse>, MfaHttpRejection> {
    let status = service.status(principal_user_id(&principal)?).await?;
    Ok(Json(status.into()))
}

#[utoipa::path(
    post,
    path = "/mfa/totp/enrollment",
    tag = "MFA",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Pending TOTP enrollment created", body = TotpEnrollmentResponse),
        (status = 401, description = "Authentication required"),
        (status = 409, description = "An active factor already exists"),
        (status = 503, description = "MFA dependency unavailable")
    )
)]
pub async fn begin_enrollment(
    CurrentSession(principal): CurrentSession,
    MfaManagementServiceHandle(service): MfaManagementServiceHandle,
) -> Result<Json<TotpEnrollmentResponse>, MfaHttpRejection> {
    let user_id = principal_user_id(&principal)?;
    let enrollment = service
        .begin_enrollment(user_id, &principal.user.username)
        .await?;
    Ok(Json(enrollment.into()))
}

#[utoipa::path(
    post,
    path = "/mfa/totp/activation",
    tag = "MFA",
    security(("bearerAuth" = [])),
    request_body(content = ConfirmTotpEnrollmentRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "TOTP enabled; recovery codes are returned once", body = RecoveryCodesResponse),
        (status = 400, description = "Malformed enrollment ID or TOTP code"),
        (status = 401, description = "Authentication required or TOTP code invalid"),
        (status = 404, description = "Enrollment not found"),
        (status = 409, description = "Enrollment expired or changed"),
        (status = 503, description = "MFA dependency unavailable")
    )
)]
pub async fn confirm_enrollment(
    CurrentSession(principal): CurrentSession,
    MfaManagementServiceHandle(service): MfaManagementServiceHandle,
    payload: Result<Json<ConfirmTotpEnrollmentRequest>, JsonRejection>,
) -> Result<Json<RecoveryCodesResponse>, MfaHttpRejection> {
    let Json(request) = payload.map_err(|_| MfaHttpRejection::BadRequest)?;
    let enrollment_id = request
        .enrollment_id
        .parse::<MfaEnrollmentId>()
        .map_err(|_| MfaHttpRejection::BadRequest)?;
    let code = TotpCode::new(request.code).map_err(|_| MfaHttpRejection::BadRequest)?;
    let activation = service
        .confirm_enrollment(principal_user_id(&principal)?, enrollment_id, &code)
        .await?;
    Ok(Json(activation.into()))
}

#[utoipa::path(
    delete,
    path = "/mfa/totp",
    tag = "MFA",
    security(("bearerAuth" = [])),
    request_body(content = MfaProofRequest, content_type = "application/json"),
    responses(
        (status = 204, description = "MFA disabled"),
        (status = 400, description = "Exactly one proof must be supplied"),
        (status = 401, description = "Authentication required or proof invalid"),
        (status = 404, description = "Active factor not found"),
        (status = 409, description = "Factor changed concurrently"),
        (status = 503, description = "MFA dependency unavailable")
    )
)]
pub async fn disable(
    CurrentSession(principal): CurrentSession,
    MfaManagementServiceHandle(service): MfaManagementServiceHandle,
    payload: Result<Json<MfaProofRequest>, JsonRejection>,
) -> Result<StatusCode, MfaHttpRejection> {
    let Json(request) = payload.map_err(|_| MfaHttpRejection::BadRequest)?;
    let proof = ParsedProof::new(request.totp_code, request.recovery_code)?;
    service
        .disable(principal_user_id(&principal)?, proof.as_proof())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/mfa/recovery-codes",
    tag = "MFA",
    security(("bearerAuth" = [])),
    request_body(content = MfaProofRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Previous recovery codes replaced", body = RecoveryCodesResponse),
        (status = 400, description = "Exactly one proof must be supplied"),
        (status = 401, description = "Authentication required or proof invalid"),
        (status = 404, description = "Active factor not found"),
        (status = 409, description = "Factor changed concurrently"),
        (status = 503, description = "MFA dependency unavailable")
    )
)]
pub async fn regenerate_recovery_codes(
    CurrentSession(principal): CurrentSession,
    MfaManagementServiceHandle(service): MfaManagementServiceHandle,
    payload: Result<Json<MfaProofRequest>, JsonRejection>,
) -> Result<Json<RecoveryCodesResponse>, MfaHttpRejection> {
    let Json(request) = payload.map_err(|_| MfaHttpRejection::BadRequest)?;
    let proof = ParsedProof::new(request.totp_code, request.recovery_code)?;
    let codes = service
        .regenerate_recovery_codes(principal_user_id(&principal)?, proof.as_proof())
        .await?;
    Ok(Json(RecoveryCodesResponse {
        recovery_codes: codes.iter().map(|code| code.as_str().to_owned()).collect(),
    }))
}

fn principal_user_id(
    principal: &crate::auth::domain::models::AuthenticatedPrincipal,
) -> Result<UserId, MfaHttpRejection> {
    UserId::new(principal.user.id).map_err(|_| MfaHttpRejection::Unauthorized)
}

fn login_proof(
    totp_code: Option<String>,
    recovery_code: Option<String>,
) -> Result<MfaLoginProof, MfaHttpRejection> {
    match (totp_code, recovery_code) {
        (Some(code), None) => TotpCode::new(code)
            .map(MfaLoginProof::Totp)
            .map_err(|_| MfaHttpRejection::BadRequest),
        (None, Some(code)) => RecoveryCode::new(code)
            .map(MfaLoginProof::RecoveryCode)
            .map_err(|_| MfaHttpRejection::BadRequest),
        _ => Err(MfaHttpRejection::BadRequest),
    }
}

enum ParsedProof {
    Totp(TotpCode),
    RecoveryCode(RecoveryCode),
}

impl ParsedProof {
    fn new(
        totp_code: Option<String>,
        recovery_code: Option<String>,
    ) -> Result<Self, MfaHttpRejection> {
        match (totp_code, recovery_code) {
            (Some(code), None) => TotpCode::new(code)
                .map(Self::Totp)
                .map_err(|_| MfaHttpRejection::BadRequest),
            (None, Some(code)) => RecoveryCode::new(code)
                .map(Self::RecoveryCode)
                .map_err(|_| MfaHttpRejection::BadRequest),
            _ => Err(MfaHttpRejection::BadRequest),
        }
    }

    fn as_proof(&self) -> MfaProof<'_> {
        match self {
            Self::Totp(code) => MfaProof::Totp(code),
            Self::RecoveryCode(code) => MfaProof::RecoveryCode(code),
        }
    }
}
