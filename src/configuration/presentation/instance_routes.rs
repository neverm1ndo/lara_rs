use axum::{
    Json,
    body::Body,
    extract::{FromRequestParts, Path, Query, rejection::QueryRejection},
    http::{
        StatusCode,
        header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG},
        request::Parts,
    },
    response::{IntoResponse, Response},
};
use tokio_util::io::ReaderStream;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    dto::{
        ConfigurationFileUpload, ConfigurationTreeResponse, ErrorResponse, FilePathQuery,
        RenameFileRequest,
    },
    instance_state::{InstanceConfigurationHandle, InstanceConfigurationState},
};
use crate::{
    auth::{
        domain::models::AuthenticatedPrincipal,
        presentation::extractors::{CurrentSession, JwtExtractorState, JwtRejection},
    },
    configuration::application::{
        instance_text::{InstanceConfigurationError, InstanceConfigurationRequest},
        target::ConfigurationAccessScope,
    },
    shared::file_storage::{mutation::MutationActor, path::RelativeStoragePath},
    shared::user_role::UserRole,
};

const TAG: &str = "Instance configuration";

pub fn router<S>() -> OpenApiRouter<S>
where
    S: InstanceConfigurationState + Clone + Send + Sync + 'static,
{
    OpenApiRouter::new()
        .routes(routes!(get_tree))
        .routes(routes!(read_file, create_file, overwrite_file, delete_file))
        .routes(routes!(rename_file))
        .routes(routes!(inspect_artifact, replace_artifact))
}

struct ConfigurationSession(AuthenticatedPrincipal);

impl<S: JwtExtractorState> FromRequestParts<S> for ConfigurationSession {
    type Rejection = HttpError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let CurrentSession(principal) = CurrentSession::from_request_parts(parts, state)
            .await
            .map_err(|error| match error {
                JwtRejection::Unauthorized => HttpError::Unauthenticated,
                JwtRejection::Unavailable => HttpError::Unavailable,
            })?;
        Ok(Self(principal))
    }
}

#[derive(Clone, Copy)]
enum HttpError {
    BadRequest,
    Unauthenticated,
    Forbidden,
    NotFound,
    Conflict,
    PreconditionFailed,
    BinaryFile,
    InvalidEncoding,
    ContentTooLarge,
    Unavailable,
}

impl From<InstanceConfigurationError> for HttpError {
    fn from(error: InstanceConfigurationError) -> Self {
        match error {
            InstanceConfigurationError::NotFound => Self::NotFound,
            InstanceConfigurationError::Forbidden => Self::Forbidden,
            InstanceConfigurationError::AlreadyExists | InstanceConfigurationError::Conflict => {
                Self::Conflict
            }
            InstanceConfigurationError::PreconditionFailed => Self::PreconditionFailed,
            InstanceConfigurationError::BinaryFile => Self::BinaryFile,
            InstanceConfigurationError::InvalidEncoding => Self::InvalidEncoding,
            InstanceConfigurationError::ContentTooLarge => Self::ContentTooLarge,
            InstanceConfigurationError::Unavailable => Self::Unavailable,
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            Self::Unauthenticated => (StatusCode::UNAUTHORIZED, "UNAUTHENTICATED"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "FORBIDDEN"),
            Self::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            Self::Conflict => (StatusCode::CONFLICT, "CONFLICT"),
            Self::PreconditionFailed => (StatusCode::PRECONDITION_FAILED, "PRECONDITION_FAILED"),
            Self::BinaryFile => (StatusCode::UNSUPPORTED_MEDIA_TYPE, "BINARY_FILE"),
            Self::InvalidEncoding => (StatusCode::UNPROCESSABLE_ENTITY, "INVALID_ENCODING"),
            Self::ContentTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "CONTENT_TOO_LARGE"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
        };
        (
            status,
            [(CACHE_CONTROL, "no-store")],
            Json(ErrorResponse { code }),
        )
            .into_response()
    }
}

fn context(
    principal: &AuthenticatedPrincipal,
    handle: &InstanceConfigurationHandle,
    instance_id: &str,
) -> Result<InstanceConfigurationRequest, HttpError> {
    let actor = MutationActor::new(
        principal.user.id.to_string(),
        Some(principal.session_id.as_str().to_owned()),
    )
    .map_err(|_| HttpError::Unavailable)?;
    InstanceConfigurationRequest::authorize(
        handle.resolver.as_ref(),
        instance_id,
        principal.user.main_group,
        &principal.user.permissions,
        actor,
    )
    .map_err(Into::into)
}

fn file_path(
    query: Result<Query<FilePathQuery>, QueryRejection>,
) -> Result<RelativeStoragePath, HttpError> {
    let Query(query) = query.map_err(|_| HttpError::BadRequest)?;
    RelativeStoragePath::new(query.path).map_err(|_| HttpError::BadRequest)
}

#[utoipa::path(get, path = "/server-instances/{instance_id}/configuration/tree", tag = TAG, security(("bearerAuth" = [])), params(("instance_id" = String, Path, description = "Instance ID")), responses((status = 200, body = ConfigurationTreeResponse), (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse), (status = 404, body = ErrorResponse), (status = 503, body = ErrorResponse)))]
async fn get_tree(
    ConfigurationSession(principal): ConfigurationSession,
    handle: InstanceConfigurationHandle,
    Path(id): Path<String>,
) -> Result<Response, HttpError> {
    let request = context(&principal, &handle, &id)?;
    let entries = handle.text.tree(request).await?;
    Ok((
        [(CACHE_CONTROL, "no-store")],
        Json(ConfigurationTreeResponse {
            entries: entries.into_iter().map(Into::into).collect(),
        }),
    )
        .into_response())
}

#[utoipa::path(get, path = "/server-instances/{instance_id}/configuration/files", tag = TAG, security(("bearerAuth" = [])), params(("instance_id" = String, Path, description = "Instance ID"), FilePathQuery), responses((status = 200, body = String, content_type = "text/plain"), (status = 400, body = ErrorResponse), (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse), (status = 404, body = ErrorResponse), (status = 415, body = ErrorResponse), (status = 503, body = ErrorResponse)))]
async fn read_file(
    ConfigurationSession(principal): ConfigurationSession,
    handle: InstanceConfigurationHandle,
    Path(id): Path<String>,
    query: Result<Query<FilePathQuery>, QueryRejection>,
) -> Result<Response, HttpError> {
    let request = context(&principal, &handle, &id)?;
    let path = file_path(query)?;
    let result = handle.text.open_text(request, path).await?;
    let content_type = format!("text/plain; charset={}", result.file.encoding_label);
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(CACHE_CONTROL, "no-store")
        .header(CONTENT_TYPE, content_type)
        .header(ETAG, result.etag.header_value());
    if let Some(length) = result.file.content_length {
        response = response.header(CONTENT_LENGTH, length);
    }
    response
        .body(Body::from_stream(ReaderStream::new(result.file.reader)))
        .map_err(|_| HttpError::Unavailable)
}

fn artifact_context(
    principal: &AuthenticatedPrincipal,
    handle: &InstanceConfigurationHandle,
    id: &str,
) -> Result<InstanceConfigurationRequest, HttpError> {
    let request = context(principal, handle, id)?;
    let developer = principal.user.main_group == UserRole::Developer
        || principal.user.permissions.contains(&UserRole::Developer);
    if !developer {
        return Err(match request.target().access_scope() {
            ConfigurationAccessScope::Auxiliary => HttpError::NotFound,
            ConfigurationAccessScope::Primary { .. } => HttpError::Forbidden,
        });
    }
    Ok(request)
}

#[utoipa::path(head, path = "/server-instances/{instance_id}/configuration/artifacts", tag = TAG, security(("bearerAuth" = [])), params(("instance_id" = String, Path, description = "Instance ID"), FilePathQuery), responses((status = 200, description = "Allowlisted artifact metadata with ETag and Content-Length"), (status = 400, body = ErrorResponse), (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse), (status = 404, body = ErrorResponse), (status = 503, body = ErrorResponse)))]
async fn inspect_artifact(
    ConfigurationSession(principal): ConfigurationSession,
    handle: InstanceConfigurationHandle,
    Path(id): Path<String>,
    query: Result<Query<FilePathQuery>, QueryRejection>,
) -> Result<Response, HttpError> {
    let request = artifact_context(&principal, &handle, &id)?;
    let path = file_path(query)?;
    let metadata = handle.artifacts.metadata(request, path).await?;
    Response::builder()
        .status(StatusCode::OK)
        .header(CACHE_CONTROL, "no-store")
        .header(ETAG, metadata.etag.header_value())
        .header(CONTENT_LENGTH, metadata.content_length)
        .body(Body::empty())
        .map_err(|_| HttpError::Unavailable)
}

// Write routes are deliberately closed until the durable intent/audit worker from step 7 is wired.
#[utoipa::path(post, path = "/server-instances/{instance_id}/configuration/files", tag = TAG, security(("bearerAuth" = [])), params(("instance_id" = String, Path, description = "Instance ID"), FilePathQuery, ("Idempotency-Key" = String, Header, description = "Required when mutation support is enabled")), request_body(content = ConfigurationFileUpload, content_type = "multipart/form-data"), responses((status = 503, description = "Durable mutation service is not yet available", body = ErrorResponse)))]
async fn create_file(
    ConfigurationSession(principal): ConfigurationSession,
    handle: InstanceConfigurationHandle,
    Path(id): Path<String>,
    query: Result<Query<FilePathQuery>, QueryRejection>,
) -> Result<Response, HttpError> {
    let _ = context(&principal, &handle, &id)?;
    let _ = file_path(query)?;
    Err(HttpError::Unavailable)
}

#[utoipa::path(put, path = "/server-instances/{instance_id}/configuration/files", tag = TAG, security(("bearerAuth" = [])), params(("instance_id" = String, Path, description = "Instance ID"), FilePathQuery, ("Idempotency-Key" = String, Header), ("If-Match" = String, Header)), request_body(content = ConfigurationFileUpload, content_type = "multipart/form-data"), responses((status = 503, description = "Durable mutation service is not yet available", body = ErrorResponse)))]
async fn overwrite_file(
    ConfigurationSession(principal): ConfigurationSession,
    handle: InstanceConfigurationHandle,
    Path(id): Path<String>,
    query: Result<Query<FilePathQuery>, QueryRejection>,
) -> Result<Response, HttpError> {
    let _ = context(&principal, &handle, &id)?;
    let _ = file_path(query)?;
    Err(HttpError::Unavailable)
}

#[utoipa::path(delete, path = "/server-instances/{instance_id}/configuration/files", tag = TAG, security(("bearerAuth" = [])), params(("instance_id" = String, Path, description = "Instance ID"), FilePathQuery, ("Idempotency-Key" = String, Header), ("If-Match" = String, Header)), responses((status = 503, description = "Durable mutation service is not yet available", body = ErrorResponse)))]
async fn delete_file(
    ConfigurationSession(principal): ConfigurationSession,
    handle: InstanceConfigurationHandle,
    Path(id): Path<String>,
    query: Result<Query<FilePathQuery>, QueryRejection>,
) -> Result<Response, HttpError> {
    let _ = context(&principal, &handle, &id)?;
    let _ = file_path(query)?;
    Err(HttpError::Unavailable)
}

#[utoipa::path(patch, path = "/server-instances/{instance_id}/configuration/files/rename", tag = TAG, security(("bearerAuth" = [])), params(("instance_id" = String, Path, description = "Instance ID"), ("Idempotency-Key" = String, Header), ("If-Match" = String, Header)), request_body = RenameFileRequest, responses((status = 503, description = "Durable mutation service is not yet available", body = ErrorResponse)))]
async fn rename_file(
    ConfigurationSession(principal): ConfigurationSession,
    handle: InstanceConfigurationHandle,
    Path(id): Path<String>,
) -> Result<Response, HttpError> {
    let _ = context(&principal, &handle, &id)?;
    Err(HttpError::Unavailable)
}

#[utoipa::path(put, path = "/server-instances/{instance_id}/configuration/artifacts", tag = TAG, security(("bearerAuth" = [])), params(("instance_id" = String, Path, description = "Instance ID"), FilePathQuery, ("Idempotency-Key" = String, Header), ("If-Match" = String, Header)), request_body(content = String, content_type = "application/octet-stream"), responses((status = 503, description = "Durable mutation service is not yet available", body = ErrorResponse)))]
async fn replace_artifact(
    ConfigurationSession(principal): ConfigurationSession,
    handle: InstanceConfigurationHandle,
    Path(id): Path<String>,
    query: Result<Query<FilePathQuery>, QueryRejection>,
) -> Result<Response, HttpError> {
    let _ = artifact_context(&principal, &handle, &id)?;
    let _ = file_path(query)?;
    Err(HttpError::Unavailable)
}
