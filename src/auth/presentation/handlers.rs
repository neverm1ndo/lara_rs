use axum::{
    Json,
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::auth::application::login::LoginError;

use super::{
    dto::{LoginRequest, LoginResponse, SessionResponse},
    extractors::CurrentSession,
    state::LoginServiceHandle,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum LoginRejection {
    BadRequest,
    Unauthorized,
    Unavailable,
}

impl IntoResponse for LoginRejection {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
        .into_response()
    }
}

impl From<LoginError> for LoginRejection {
    fn from(error: LoginError) -> Self {
        match error {
            LoginError::InvalidCredentials => Self::Unauthorized,
            LoginError::Unavailable => Self::Unavailable,
        }
    }
}

#[utoipa::path(
    post,
    path = "/login",
    tag = "Authentication",
    request_body(
        content = LoginRequest,
        description = "User credentials",
        content_type = "application/json"
    ),
    responses(
        (status = 200, description = "Credentials accepted and a server-side session created", body = LoginResponse),
        (status = 400, description = "Malformed JSON request"),
        (status = 401, description = "Invalid credentials or user is outside the work group"),
        (status = 503, description = "Authentication dependencies are unavailable")
    )
)]
#[allow(dead_code)]
pub async fn login(
    LoginServiceHandle(login_service): LoginServiceHandle,
    payload: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Json<LoginResponse>, LoginRejection> {
    let Json(request) = payload.map_err(|_| LoginRejection::BadRequest)?;
    let result = login_service
        .login(&request.email, &request.password)
        .await?;

    Ok(Json(result.into()))
}

#[utoipa::path(
    get,
    path = "/session",
    tag = "Authentication",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "The JWT, server-side session and current work-group membership are valid", body = SessionResponse),
        (status = 401, description = "Bearer token or session is invalid or expired", body = String, content_type = "text/plain"),
        (status = 503, description = "Authentication dependencies are unavailable", body = String, content_type = "text/plain")
    )
)]
pub async fn get_session(CurrentSession(principal): CurrentSession) -> Json<SessionResponse> {
    Json(principal.into())
}
