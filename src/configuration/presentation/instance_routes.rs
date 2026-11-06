use axum::{
    Json,
    body::Body,
    extract::{
        FromRequestParts, Path, Query, Request,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{
        HeaderMap, StatusCode,
        header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_MATCH},
        request::Parts,
    },
    response::{IntoResponse, Response},
};
use tokio_util::io::ReaderStream;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    dto::{
        ConfigurationFileUpload, ConfigurationMutationResponse, ConfigurationTreeResponse,
        ErrorResponse, FilePathQuery, RenameFileRequest,
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
        mutation_service::{
            ConfigurationMutationCommand, ConfigurationMutationKind, ConfigurationMutationResult,
            ConfigurationMutationServiceError,
        },
        target::ConfigurationAccessScope,
    },
    shared::file_storage::{
        mutation::MutationActor,
        path::RelativeStoragePath,
        upload::{MultipartUploadLimits, collect_multipart_upload},
    },
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

#[derive(Debug, Clone)]
enum HttpError {
    BadRequest,
    Unauthenticated,
    Forbidden,
    NotFound,
    Conflict,
    PreconditionFailed,
    PreconditionRequired,
    BinaryFile,
    InvalidEncoding,
    ContentTooLarge,
    Unavailable,
    ReconciliationRequired(String),
    Reviewed(String),
}

impl From<ConfigurationMutationServiceError> for HttpError {
    fn from(error: ConfigurationMutationServiceError) -> Self {
        match error {
            ConfigurationMutationServiceError::Conflict => Self::Conflict,
            ConfigurationMutationServiceError::ReconciliationRequired(id) => {
                Self::ReconciliationRequired(id)
            }
            ConfigurationMutationServiceError::Reviewed(id) => Self::Reviewed(id),
            ConfigurationMutationServiceError::Unavailable => Self::Unavailable,
            ConfigurationMutationServiceError::Application(error) => error.into(),
        }
    }
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
        if let Self::ReconciliationRequired(mutation_id) = &self {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [(CACHE_CONTROL, "no-store")],
                Json(serde_json::json!({"code": "SERVICE_UNAVAILABLE", "mutationId": mutation_id})),
            )
                .into_response();
        }
        if let Self::Reviewed(mutation_id) = &self {
            return (
                StatusCode::CONFLICT,
                [(CACHE_CONTROL, "no-store")],
                Json(serde_json::json!({"code": "CONFLICT", "mutationId": mutation_id})),
            )
                .into_response();
        }
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            Self::Unauthenticated => (StatusCode::UNAUTHORIZED, "UNAUTHENTICATED"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "FORBIDDEN"),
            Self::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            Self::Conflict => (StatusCode::CONFLICT, "CONFLICT"),
            Self::PreconditionFailed => (StatusCode::PRECONDITION_FAILED, "PRECONDITION_FAILED"),
            Self::PreconditionRequired => {
                (StatusCode::PRECONDITION_REQUIRED, "PRECONDITION_REQUIRED")
            }
            Self::BinaryFile => (StatusCode::UNSUPPORTED_MEDIA_TYPE, "BINARY_FILE"),
            Self::InvalidEncoding => (StatusCode::UNPROCESSABLE_ENTITY, "INVALID_ENCODING"),
            Self::ContentTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "CONTENT_TOO_LARGE"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
            Self::ReconciliationRequired(_) => unreachable!(),
            Self::Reviewed(_) => unreachable!(),
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

fn mutation_headers(
    headers: &HeaderMap,
    conditional: bool,
) -> Result<
    (
        String,
        Option<crate::configuration::application::instance_text::ConfigurationEntityTag>,
    ),
    HttpError,
> {
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or(HttpError::BadRequest)?;
    if key.is_empty() || key.len() > 128 || !key.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(HttpError::BadRequest);
    }
    let expected = if conditional {
        let value = headers
            .get(IF_MATCH)
            .ok_or(HttpError::PreconditionRequired)?
            .to_str()
            .map_err(|_| HttpError::BadRequest)?;
        Some(
            crate::configuration::application::instance_text::ConfigurationEntityTag::parse(value)
                .map_err(|_| HttpError::BadRequest)?,
        )
    } else {
        None
    };
    Ok((key.to_owned(), expected))
}

async fn text_upload(request: Request, limit: u64) -> Result<Vec<u8>, HttpError> {
    let limits = MultipartUploadLimits::single_part(limit).map_err(|_| HttpError::Unavailable)?;
    let mut parts = collect_multipart_upload(request, limits)
        .await
        .map_err(|error| {
            if error.is_too_large() {
                HttpError::ContentTooLarge
            } else {
                HttpError::BadRequest
            }
        })?
        .into_parts();
    let part = parts.pop().ok_or(HttpError::BadRequest)?;
    if part.name() != "file" || !parts.is_empty() {
        return Err(HttpError::BadRequest);
    }
    Ok(part.into_bytes())
}

fn mutation_response(result: ConfigurationMutationResult, created: bool) -> Response {
    let event = result.event;
    let current_hash = event.current_hash.clone();
    let body = ConfigurationMutationResponse {
        mutation_id: event.mutation_id,
        instance_id: event.instance_id,
        status: "succeeded",
        event_id: event.event_id,
        event_type: crate::configuration::domain::CONFIGURATION_FILE_CHANGED_EVENT_TYPE,
        occurred_at: event.occurred_at,
    };
    let mut response = (
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        [(CACHE_CONTROL, "no-store")],
        Json(body),
    )
        .into_response();
    if result.replayed {
        response.headers_mut().insert(
            "idempotency-replayed",
            "true".parse().expect("header value"),
        );
    }
    if let Some(hash) = current_hash
        && let Ok(value) = format!("\"{hash}\"").parse()
    {
        response.headers_mut().insert(ETAG, value);
    }
    response
}

#[utoipa::path(post, path = "/server-instances/{instance_id}/configuration/files", tag = TAG, security(("bearerAuth" = [])), params(("instance_id" = String, Path, description = "Instance ID"), FilePathQuery, ("Idempotency-Key" = String, Header, description = "Required for idempotent mutation")), request_body(content = ConfigurationFileUpload, content_type = "multipart/form-data"), responses((status = 201, body = ConfigurationMutationResponse), (status = 400, body = ErrorResponse), (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse), (status = 404, body = ErrorResponse), (status = 409, body = ErrorResponse), (status = 413, body = ErrorResponse), (status = 422, body = ErrorResponse), (status = 503, body = ErrorResponse)))]
async fn create_file(
    ConfigurationSession(principal): ConfigurationSession,
    handle: InstanceConfigurationHandle,
    Path(id): Path<String>,
    query: Result<Query<FilePathQuery>, QueryRejection>,
    request: Request,
) -> Result<Response, HttpError> {
    let context = context(&principal, &handle, &id)?;
    let path = file_path(query)?;
    let (key, _) = mutation_headers(request.headers(), false)?;
    let content = text_upload(
        request,
        context.target().storage().limits().max_stream_size_bytes,
    )
    .await?;
    let result = handle
        .mutations
        .execute(
            context,
            ConfigurationMutationCommand {
                kind: ConfigurationMutationKind::Create,
                source: None,
                destination: Some(path),
                expected: None,
                content: Some(content),
                idempotency_key: key,
            },
        )
        .await?;
    Ok(mutation_response(result, true))
}

#[utoipa::path(put, path = "/server-instances/{instance_id}/configuration/files", tag = TAG, security(("bearerAuth" = [])), params(("instance_id" = String, Path, description = "Instance ID"), FilePathQuery, ("Idempotency-Key" = String, Header), ("If-Match" = String, Header)), request_body(content = ConfigurationFileUpload, content_type = "multipart/form-data"), responses((status = 200, body = ConfigurationMutationResponse), (status = 400, body = ErrorResponse), (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse), (status = 404, body = ErrorResponse), (status = 409, body = ErrorResponse), (status = 412, body = ErrorResponse), (status = 413, body = ErrorResponse), (status = 415, body = ErrorResponse), (status = 422, body = ErrorResponse), (status = 428, body = ErrorResponse), (status = 503, body = ErrorResponse)))]
async fn overwrite_file(
    ConfigurationSession(principal): ConfigurationSession,
    handle: InstanceConfigurationHandle,
    Path(id): Path<String>,
    query: Result<Query<FilePathQuery>, QueryRejection>,
    request: Request,
) -> Result<Response, HttpError> {
    let context = context(&principal, &handle, &id)?;
    let path = file_path(query)?;
    let (key, expected) = mutation_headers(request.headers(), true)?;
    let content = text_upload(
        request,
        context.target().storage().limits().max_stream_size_bytes,
    )
    .await?;
    let result = handle
        .mutations
        .execute(
            context,
            ConfigurationMutationCommand {
                kind: ConfigurationMutationKind::Overwrite,
                source: Some(path),
                destination: None,
                expected,
                content: Some(content),
                idempotency_key: key,
            },
        )
        .await?;
    Ok(mutation_response(result, false))
}

#[utoipa::path(delete, path = "/server-instances/{instance_id}/configuration/files", tag = TAG, security(("bearerAuth" = [])), params(("instance_id" = String, Path, description = "Instance ID"), FilePathQuery, ("Idempotency-Key" = String, Header), ("If-Match" = String, Header)), responses((status = 200, body = ConfigurationMutationResponse), (status = 400, body = ErrorResponse), (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse), (status = 404, body = ErrorResponse), (status = 409, body = ErrorResponse), (status = 412, body = ErrorResponse), (status = 415, body = ErrorResponse), (status = 428, body = ErrorResponse), (status = 503, body = ErrorResponse)))]
async fn delete_file(
    ConfigurationSession(principal): ConfigurationSession,
    handle: InstanceConfigurationHandle,
    Path(id): Path<String>,
    query: Result<Query<FilePathQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let context = context(&principal, &handle, &id)?;
    let path = file_path(query)?;
    let (key, expected) = mutation_headers(&headers, true)?;
    let result = handle
        .mutations
        .execute(
            context,
            ConfigurationMutationCommand {
                kind: ConfigurationMutationKind::Delete,
                source: Some(path),
                destination: None,
                expected,
                content: None,
                idempotency_key: key,
            },
        )
        .await?;
    Ok(mutation_response(result, false))
}

#[utoipa::path(patch, path = "/server-instances/{instance_id}/configuration/files/rename", tag = TAG, security(("bearerAuth" = [])), params(("instance_id" = String, Path, description = "Instance ID"), ("Idempotency-Key" = String, Header), ("If-Match" = String, Header)), request_body = RenameFileRequest, responses((status = 200, body = ConfigurationMutationResponse), (status = 400, body = ErrorResponse), (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse), (status = 404, body = ErrorResponse), (status = 409, body = ErrorResponse), (status = 412, body = ErrorResponse), (status = 415, body = ErrorResponse), (status = 428, body = ErrorResponse), (status = 503, body = ErrorResponse)))]
async fn rename_file(
    ConfigurationSession(principal): ConfigurationSession,
    handle: InstanceConfigurationHandle,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<RenameFileRequest>, JsonRejection>,
) -> Result<Response, HttpError> {
    let context = context(&principal, &handle, &id)?;
    let (key, expected) = mutation_headers(&headers, true)?;
    let Json(body) = body.map_err(|_| HttpError::BadRequest)?;
    let source = RelativeStoragePath::new(body.source).map_err(|_| HttpError::BadRequest)?;
    let destination =
        RelativeStoragePath::new(body.destination).map_err(|_| HttpError::BadRequest)?;
    let result = handle
        .mutations
        .execute(
            context,
            ConfigurationMutationCommand {
                kind: ConfigurationMutationKind::Rename,
                source: Some(source),
                destination: Some(destination),
                expected,
                content: None,
                idempotency_key: key,
            },
        )
        .await?;
    Ok(mutation_response(result, false))
}

#[utoipa::path(put, path = "/server-instances/{instance_id}/configuration/artifacts", tag = TAG, security(("bearerAuth" = [])), params(("instance_id" = String, Path, description = "Instance ID"), FilePathQuery, ("Idempotency-Key" = String, Header), ("If-Match" = String, Header)), request_body(content = String, content_type = "application/octet-stream"), responses((status = 200, body = ConfigurationMutationResponse), (status = 400, body = ErrorResponse), (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse), (status = 404, body = ErrorResponse), (status = 409, body = ErrorResponse), (status = 412, body = ErrorResponse), (status = 413, body = ErrorResponse), (status = 428, body = ErrorResponse), (status = 503, body = ErrorResponse)))]
async fn replace_artifact(
    ConfigurationSession(principal): ConfigurationSession,
    handle: InstanceConfigurationHandle,
    Path(id): Path<String>,
    query: Result<Query<FilePathQuery>, QueryRejection>,
    request: Request,
) -> Result<Response, HttpError> {
    let context = artifact_context(&principal, &handle, &id)?;
    let path = file_path(query)?;
    let (key, expected) = mutation_headers(request.headers(), true)?;
    if request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/octet-stream")
    {
        return Err(HttpError::BadRequest);
    }
    let limit = usize::try_from(context.target().storage().limits().max_stream_size_bytes)
        .unwrap_or(usize::MAX);
    let content = axum::body::to_bytes(request.into_body(), limit.saturating_add(1))
        .await
        .map_err(|_| HttpError::ContentTooLarge)?
        .to_vec();
    if content.len() > limit {
        return Err(HttpError::ContentTooLarge);
    }
    let result = handle
        .mutations
        .execute(
            context,
            ConfigurationMutationCommand {
                kind: ConfigurationMutationKind::ReplaceArtifact,
                source: Some(path),
                destination: None,
                expected,
                content: Some(content),
                idempotency_key: key,
            },
        )
        .await?;
    Ok(mutation_response(result, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_headers_require_visible_ascii_key_and_strong_if_match() {
        let mut headers = HeaderMap::new();
        assert!(matches!(
            mutation_headers(&headers, false),
            Err(HttpError::BadRequest)
        ));
        headers.insert("idempotency-key", "request 1".parse().unwrap());
        assert!(matches!(
            mutation_headers(&headers, false),
            Err(HttpError::BadRequest)
        ));
        headers.insert("idempotency-key", "request-1".parse().unwrap());
        assert!(matches!(
            mutation_headers(&headers, true),
            Err(HttpError::PreconditionRequired)
        ));
        headers.insert(IF_MATCH, "W/\"sha256:abc\"".parse().unwrap());
        assert!(matches!(
            mutation_headers(&headers, true),
            Err(HttpError::BadRequest)
        ));
        headers.insert(
            IF_MATCH,
            format!("\"sha256:{}\"", "a".repeat(64)).parse().unwrap(),
        );
        let (key, tag) = mutation_headers(&headers, true).unwrap();
        assert_eq!(key, "request-1");
        assert!(tag.is_some());
    }
}
