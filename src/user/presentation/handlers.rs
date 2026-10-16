use axum::{
    Json,
    extract::{Path, rejection::PathRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::{
    auth::presentation::extractors::CurrentSession,
    user::{
        application::get_user::GetUserError,
        domain::profile::UserId,
        presentation::{
            dto::{UserErrorResponse, UserResponse},
            state::UserServiceHandle,
        },
    },
};

const TAG: &str = "Users";

#[utoipa::path(
    get,
    path = "/{id}",
    tag = TAG,
    security(("bearerAuth" = [])),
    params(("id" = i64, Path, description = "Positive phpBB user identifier")),
    responses(
        (status = 200, description = "Workspace user profile", body = UserResponse),
        (status = 400, description = "User identifier is invalid", body = UserErrorResponse),
        (status = 401, description = "Bearer token or session is invalid or expired", body = String, content_type = "text/plain"),
        (status = 404, description = "Workspace user does not exist", body = UserErrorResponse),
        (status = 503, description = "Authentication or user dependency is unavailable", body = UserErrorResponse)
    )
)]
pub async fn get_user(
    _session: CurrentSession,
    UserServiceHandle(service): UserServiceHandle,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Json<UserResponse>, UserHttpError> {
    let Path(id) = id.map_err(|_| UserHttpError::BadRequest)?;
    let id = UserId::new(id).map_err(|_| UserHttpError::BadRequest)?;
    let profile = service.get_user(id).await?;

    Ok(Json(profile.into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserHttpError {
    BadRequest,
    NotFound,
    Unavailable,
}

impl From<GetUserError> for UserHttpError {
    fn from(error: GetUserError) -> Self {
        match error {
            GetUserError::NotFound => Self::NotFound,
            GetUserError::Unavailable => Self::Unavailable,
        }
    }
}

impl IntoResponse for UserHttpError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "INVALID_USER_ID"),
            Self::NotFound => (StatusCode::NOT_FOUND, "USER_NOT_FOUND"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
        };

        (status, Json(UserErrorResponse { code })).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_application_errors_to_http_statuses() {
        assert_eq!(
            UserHttpError::from(GetUserError::NotFound)
                .into_response()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            UserHttpError::from(GetUserError::Unavailable)
                .into_response()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
