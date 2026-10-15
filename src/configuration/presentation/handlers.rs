use axum::{
    Json,
    body::Body,
    extract::{
        Multipart, Query,
        multipart::{MultipartError, MultipartRejection},
        rejection::{JsonRejection, QueryRejection},
    },
    http::{
        HeaderValue, StatusCode,
        header::{CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
};
use tokio_util::io::ReaderStream;

use super::{
    authorization::AuthorizedConfiguration,
    dto::{
        ConfigurationFileUpload, ConfigurationTreeResponse, ErrorResponse, FileMutationResponse,
        FilePathQuery, RenameFileRequest,
    },
    state::ConfigurationServiceHandle,
};
use crate::{
    configuration::application::file_service::{
        ConfigurationFileContent, ConfigurationFileServiceError, ConfigurationRequestContext,
        ConfigurationTextFile,
    },
    shared::file_storage::{mutation::MutationActor, path::RelativeStoragePath},
};

const TAG: &str = "Server configuration";

#[utoipa::path(
    get,
    path = "/tree",
    tag = TAG,
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "File tree limited to the caller's capability", body = ConfigurationTreeResponse),
        (status = 401, description = "Bearer token or session is invalid", body = ErrorResponse),
        (status = 403, description = "Developer or configurator role is required", body = ErrorResponse),
        (status = 503, description = "Configuration service is unavailable", body = ErrorResponse)
    )
)]
pub async fn get_tree(
    authorized: AuthorizedConfiguration,
    ConfigurationServiceHandle { service, .. }: ConfigurationServiceHandle,
) -> Result<Json<ConfigurationTreeResponse>, ConfigurationHttpError> {
    let entries = service.tree(request_context(authorized)).await?;
    Ok(Json(ConfigurationTreeResponse {
        entries: entries.into_iter().map(Into::into).collect(),
    }))
}

#[utoipa::path(
    get,
    path = "/files",
    tag = TAG,
    security(("bearerAuth" = [])),
    params(FilePathQuery),
    responses(
        (status = 200, description = "Raw text bytes in the configured legacy encoding", body = String, content_type = "text/plain; charset=windows-1251"),
        (status = 400, description = "Malformed or unsafe relative path", body = ErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = ErrorResponse),
        (status = 403, description = "Developer or configurator role is required", body = ErrorResponse),
        (status = 404, description = "File does not exist or is hidden by policy", body = ErrorResponse),
        (status = 415, description = "Binary files cannot be read as configuration text", body = ErrorResponse),
        (status = 503, description = "Configuration service is unavailable", body = ErrorResponse)
    )
)]
pub async fn read_file(
    authorized: AuthorizedConfiguration,
    ConfigurationServiceHandle { service, .. }: ConfigurationServiceHandle,
    query: Result<Query<FilePathQuery>, QueryRejection>,
) -> Result<Response, ConfigurationHttpError> {
    let Query(query) = query.map_err(|_| ConfigurationHttpError::BadRequest)?;
    let path = parse_path(&query.path)?;
    let file = service.open_text(request_context(authorized), path).await?;
    stream_response(file)
}

#[utoipa::path(
    post,
    path = "/files",
    tag = TAG,
    security(("bearerAuth" = [])),
    params(FilePathQuery),
    request_body(content = ConfigurationFileUpload, description = "Multipart upload with one binary field named `file`; its bytes must use the configured server encoding", content_type = "multipart/form-data"),
    responses(
        (status = 201, description = "Text file created", body = FileMutationResponse),
        (status = 400, description = "Malformed request or unsafe relative path", body = ErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = ErrorResponse),
        (status = 403, description = "Developer or configurator role is required", body = ErrorResponse),
        (status = 409, description = "Destination already exists", body = ErrorResponse),
        (status = 413, description = "Content exceeds the configured limit", body = ErrorResponse),
        (status = 422, description = "File bytes are invalid for the configured encoding", body = ErrorResponse),
        (status = 503, description = "Configuration service is unavailable", body = ErrorResponse)
    )
)]
pub async fn create_file(
    authorized: AuthorizedConfiguration,
    ConfigurationServiceHandle { service, encoding }: ConfigurationServiceHandle,
    query: Result<Query<FilePathQuery>, QueryRejection>,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<impl IntoResponse, ConfigurationHttpError> {
    let Query(query) = query.map_err(|_| ConfigurationHttpError::BadRequest)?;
    let path = parse_path(&query.path)?;
    let content = multipart_content(multipart, encoding).await?;
    let event = service
        .create(request_context(authorized), path, content)
        .await?;
    Ok((StatusCode::CREATED, Json(FileMutationResponse::from(event))))
}

#[utoipa::path(
    put,
    path = "/files",
    tag = TAG,
    security(("bearerAuth" = [])),
    params(FilePathQuery),
    request_body(content = ConfigurationFileUpload, description = "Multipart upload with one binary field named `file`; its bytes must use the configured server encoding", content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "Text file overwritten", body = FileMutationResponse),
        (status = 400, description = "Malformed request or unsafe relative path", body = ErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = ErrorResponse),
        (status = 403, description = "Developer or configurator role is required", body = ErrorResponse),
        (status = 404, description = "File does not exist or is hidden by policy", body = ErrorResponse),
        (status = 409, description = "File changed concurrently", body = ErrorResponse),
        (status = 413, description = "Content exceeds the configured limit", body = ErrorResponse),
        (status = 422, description = "File bytes are invalid for the configured encoding", body = ErrorResponse),
        (status = 503, description = "Configuration service is unavailable", body = ErrorResponse)
    )
)]
pub async fn overwrite_file(
    authorized: AuthorizedConfiguration,
    ConfigurationServiceHandle { service, encoding }: ConfigurationServiceHandle,
    query: Result<Query<FilePathQuery>, QueryRejection>,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Json<FileMutationResponse>, ConfigurationHttpError> {
    let Query(query) = query.map_err(|_| ConfigurationHttpError::BadRequest)?;
    let path = parse_path(&query.path)?;
    let content = multipart_content(multipart, encoding).await?;
    let event = service
        .overwrite(request_context(authorized), path, content)
        .await?;
    Ok(Json(event.into()))
}

#[utoipa::path(
    delete,
    path = "/files",
    tag = TAG,
    security(("bearerAuth" = [])),
    params(FilePathQuery),
    responses(
        (status = 200, description = "File deleted", body = FileMutationResponse),
        (status = 400, description = "Malformed or unsafe relative path", body = ErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = ErrorResponse),
        (status = 403, description = "Developer or configurator role is required", body = ErrorResponse),
        (status = 404, description = "File does not exist or is hidden by policy", body = ErrorResponse),
        (status = 409, description = "File changed concurrently", body = ErrorResponse),
        (status = 503, description = "Configuration service is unavailable", body = ErrorResponse)
    )
)]
pub async fn delete_file(
    authorized: AuthorizedConfiguration,
    ConfigurationServiceHandle { service, .. }: ConfigurationServiceHandle,
    query: Result<Query<FilePathQuery>, QueryRejection>,
) -> Result<Json<FileMutationResponse>, ConfigurationHttpError> {
    let Query(query) = query.map_err(|_| ConfigurationHttpError::BadRequest)?;
    let path = parse_path(&query.path)?;
    let event = service.delete(request_context(authorized), path).await?;
    Ok(Json(event.into()))
}

#[utoipa::path(
    patch,
    path = "/files/rename",
    tag = TAG,
    security(("bearerAuth" = [])),
    request_body(content = RenameFileRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "File renamed", body = FileMutationResponse),
        (status = 400, description = "Malformed request or unsafe relative path", body = ErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = ErrorResponse),
        (status = 403, description = "Developer or configurator role is required", body = ErrorResponse),
        (status = 404, description = "Source does not exist or is hidden by policy", body = ErrorResponse),
        (status = 409, description = "Destination exists or source changed concurrently", body = ErrorResponse),
        (status = 503, description = "Configuration service is unavailable", body = ErrorResponse)
    )
)]
pub async fn rename_file(
    authorized: AuthorizedConfiguration,
    ConfigurationServiceHandle { service, .. }: ConfigurationServiceHandle,
    payload: Result<Json<RenameFileRequest>, JsonRejection>,
) -> Result<Json<FileMutationResponse>, ConfigurationHttpError> {
    let Json(payload) = payload.map_err(|_| ConfigurationHttpError::BadRequest)?;
    let source = parse_path(&payload.source)?;
    let destination = parse_path(&payload.destination)?;
    let event = service
        .rename(request_context(authorized), source, destination)
        .await?;
    Ok(Json(event.into()))
}

fn request_context(authorized: AuthorizedConfiguration) -> ConfigurationRequestContext {
    let (principal, access) = authorized.into_parts();
    let actor = MutationActor::new(
        principal.user.id.to_string(),
        Some(principal.session_id.as_str().to_owned()),
    )
    .expect("authenticated principal always produces a valid mutation actor");
    ConfigurationRequestContext::new(access, actor)
}

fn parse_path(value: &str) -> Result<RelativeStoragePath, ConfigurationHttpError> {
    RelativeStoragePath::new(value).map_err(|_| ConfigurationHttpError::BadRequest)
}

async fn multipart_content(
    multipart: Result<Multipart, MultipartRejection>,
    encoding: &'static encoding_rs::Encoding,
) -> Result<ConfigurationFileContent, ConfigurationHttpError> {
    let mut multipart = multipart.map_err(|_| ConfigurationHttpError::BadRequest)?;
    let mut content = None;

    while let Some(field) = multipart.next_field().await.map_err(map_multipart_error)? {
        if field.name() != Some("file") || content.is_some() {
            return Err(ConfigurationHttpError::BadRequest);
        }
        content = Some(field.bytes().await.map_err(map_multipart_error)?.to_vec());
    }

    let bytes = content.ok_or(ConfigurationHttpError::BadRequest)?;
    ConfigurationFileContent::validate(bytes, encoding).map_err(Into::into)
}

fn map_multipart_error(error: MultipartError) -> ConfigurationHttpError {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ConfigurationHttpError::ContentTooLarge
    } else {
        ConfigurationHttpError::BadRequest
    }
}

fn stream_response(file: ConfigurationTextFile) -> Result<Response, ConfigurationHttpError> {
    let content_type =
        HeaderValue::from_str(&format!("text/plain; charset={}", file.encoding_label))
            .map_err(|_| ConfigurationHttpError::Unavailable)?;
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(
            CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("inline; filename=\"{}\"", file.file_name))
                .map_err(|_| ConfigurationHttpError::Unavailable)?,
        );
    if let Some(length) = file.content_length {
        builder = builder.header(CONTENT_LENGTH, length);
    }
    builder
        .body(Body::from_stream(ReaderStream::new(file.reader)))
        .map_err(|_| ConfigurationHttpError::Unavailable)
}

#[derive(Debug, Clone, Copy)]
pub enum ConfigurationHttpError {
    BadRequest,
    NotFound,
    Conflict,
    UnsupportedMediaType,
    InvalidEncoding,
    ContentTooLarge,
    Unavailable,
}

impl From<ConfigurationFileServiceError> for ConfigurationHttpError {
    fn from(error: ConfigurationFileServiceError) -> Self {
        match error {
            ConfigurationFileServiceError::NotFound => Self::NotFound,
            ConfigurationFileServiceError::AlreadyExists
            | ConfigurationFileServiceError::Conflict => Self::Conflict,
            ConfigurationFileServiceError::BinaryFile => Self::UnsupportedMediaType,
            ConfigurationFileServiceError::InvalidEncoding => Self::InvalidEncoding,
            ConfigurationFileServiceError::ContentTooLarge => Self::ContentTooLarge,
            ConfigurationFileServiceError::Unavailable
            | ConfigurationFileServiceError::Stream(_) => Self::Unavailable,
        }
    }
}

impl IntoResponse for ConfigurationHttpError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            Self::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            Self::Conflict => (StatusCode::CONFLICT, "CONFLICT"),
            Self::UnsupportedMediaType => (StatusCode::UNSUPPORTED_MEDIA_TYPE, "BINARY_FILE"),
            Self::InvalidEncoding => (StatusCode::UNPROCESSABLE_ENTITY, "INVALID_ENCODING"),
            Self::ContentTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "CONTENT_TOO_LARGE"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
        };
        (status, Json(ErrorResponse { code })).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_application_errors_to_stable_http_responses() {
        let cases = [
            (ConfigurationHttpError::BadRequest, StatusCode::BAD_REQUEST),
            (ConfigurationHttpError::NotFound, StatusCode::NOT_FOUND),
            (ConfigurationHttpError::Conflict, StatusCode::CONFLICT),
            (
                ConfigurationHttpError::UnsupportedMediaType,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                ConfigurationHttpError::ContentTooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                ConfigurationHttpError::InvalidEncoding,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                ConfigurationHttpError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ];

        for (error, status) in cases {
            assert_eq!(error.into_response().status(), status);
        }
    }

    #[test]
    fn rejects_unsafe_paths_at_the_http_boundary() {
        for path in ["", "../server.cfg", "C:\\server.cfg", "config//file.cfg"] {
            assert!(matches!(
                parse_path(path),
                Err(ConfigurationHttpError::BadRequest)
            ));
        }
    }
}
