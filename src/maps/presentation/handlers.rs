use axum::{
    Json,
    body::Body,
    extract::{
        Query, Request,
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
    authorization::AuthorizedMaps,
    dto::{
        MapFileMutationResponse, MapFileMutationsResponse, MapFilePathQuery, MapFilesUpload,
        MapsErrorResponse, MapsTreeResponse, RenameMapFileRequest,
    },
    state::MapsServiceHandle,
};
use crate::{
    maps::{
        application::file_service::{
            InvalidMapUploadBatch, MapUpload, MapUploadBatch, MapsFileServiceError,
            MapsRequestContext, OpenedMapFile,
        },
        domain::MapFilePath,
    },
    shared::file_storage::{
        mutation::MutationActor,
        path::RelativeStoragePath,
        upload::{MultipartUploadError, MultipartUploadLimits, collect_multipart_upload},
    },
};

const TAG: &str = "Server maps";

#[utoipa::path(
    get,
    path = "/tree",
    tag = TAG,
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Recursive tree containing only .map and .map.off files", body = MapsTreeResponse),
        (status = 401, description = "Bearer token or session is invalid", body = MapsErrorResponse),
        (status = 403, description = "Developer or mapper role is required", body = MapsErrorResponse),
        (status = 503, description = "Maps service is unavailable", body = MapsErrorResponse)
    )
)]
pub async fn get_tree(
    authorized: AuthorizedMaps,
    MapsServiceHandle { service, .. }: MapsServiceHandle,
) -> Result<Json<MapsTreeResponse>, MapsHttpError> {
    let entries = service.tree(request_context(authorized)).await?;
    Ok(Json(MapsTreeResponse {
        entries: entries.into_iter().map(Into::into).collect(),
    }))
}

#[utoipa::path(
    get,
    path = "/files",
    tag = TAG,
    security(("bearerAuth" = [])),
    params(MapFilePathQuery),
    responses(
        (status = 200, description = "Raw map bytes without XML parsing or transcoding", body = String, content_type = "application/xml"),
        (status = 400, description = "Malformed, unsafe or unsupported map path", body = MapsErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = MapsErrorResponse),
        (status = 403, description = "Developer or mapper role is required", body = MapsErrorResponse),
        (status = 404, description = "Map file does not exist", body = MapsErrorResponse),
        (status = 413, description = "Map exceeds the configured streaming limit", body = MapsErrorResponse),
        (status = 503, description = "Maps service is unavailable", body = MapsErrorResponse)
    )
)]
pub async fn read_file(
    authorized: AuthorizedMaps,
    MapsServiceHandle { service, .. }: MapsServiceHandle,
    query: Result<Query<MapFilePathQuery>, QueryRejection>,
) -> Result<Response, MapsHttpError> {
    let Query(query) = query.map_err(|_| MapsHttpError::BadRequest)?;
    let path = parse_map_path(&query.path)?;
    let file = service.open(request_context(authorized), path).await?;
    stream_response(file)
}

#[utoipa::path(
    post,
    path = "/files",
    tag = TAG,
    security(("bearerAuth" = [])),
    request_body(
        content = MapFilesUpload,
        description = "One or more binary parts named `files`. Each filename is a relative .map or .map.off destination path.",
        content_type = "multipart/form-data"
    ),
    responses(
        (status = 201, description = "Map files created", body = MapFileMutationsResponse),
        (status = 400, description = "Malformed multipart body, invalid path or duplicate destination", body = MapsErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = MapsErrorResponse),
        (status = 403, description = "Developer or mapper role is required", body = MapsErrorResponse),
        (status = 409, description = "At least one destination already exists", body = MapsErrorResponse),
        (status = 413, description = "File count, file size or total size exceeds configured limits", body = MapsErrorResponse),
        (status = 503, description = "Maps service is unavailable", body = MapsErrorResponse)
    )
)]
pub async fn create_files(
    authorized: AuthorizedMaps,
    MapsServiceHandle {
        service,
        upload_limits,
    }: MapsServiceHandle,
    request: Request,
) -> Result<impl IntoResponse, MapsHttpError> {
    let batch = multipart_batch(request, upload_limits).await?;
    let events = service
        .create_many(request_context(authorized), batch)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(MapFileMutationsResponse::from(events)),
    ))
}

#[utoipa::path(
    put,
    path = "/files",
    tag = TAG,
    security(("bearerAuth" = [])),
    request_body(
        content = MapFilesUpload,
        description = "One or more binary parts named `files`. Each filename is a relative existing .map or .map.off path.",
        content_type = "multipart/form-data"
    ),
    responses(
        (status = 200, description = "Map files overwritten", body = MapFileMutationsResponse),
        (status = 400, description = "Malformed multipart body, invalid path or duplicate destination", body = MapsErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = MapsErrorResponse),
        (status = 403, description = "Developer or mapper role is required", body = MapsErrorResponse),
        (status = 404, description = "At least one map file does not exist", body = MapsErrorResponse),
        (status = 409, description = "A map changed concurrently", body = MapsErrorResponse),
        (status = 413, description = "File count, file size or total size exceeds configured limits", body = MapsErrorResponse),
        (status = 503, description = "Maps service is unavailable", body = MapsErrorResponse)
    )
)]
pub async fn overwrite_files(
    authorized: AuthorizedMaps,
    MapsServiceHandle {
        service,
        upload_limits,
    }: MapsServiceHandle,
    request: Request,
) -> Result<Json<MapFileMutationsResponse>, MapsHttpError> {
    let batch = multipart_batch(request, upload_limits).await?;
    let events = service
        .overwrite_many(request_context(authorized), batch)
        .await?;
    Ok(Json(events.into()))
}

#[utoipa::path(
    delete,
    path = "/files",
    tag = TAG,
    security(("bearerAuth" = [])),
    params(MapFilePathQuery),
    responses(
        (status = 200, description = "Map file deleted", body = MapFileMutationResponse),
        (status = 400, description = "Malformed, unsafe or unsupported map path", body = MapsErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = MapsErrorResponse),
        (status = 403, description = "Developer or mapper role is required", body = MapsErrorResponse),
        (status = 404, description = "Map file does not exist", body = MapsErrorResponse),
        (status = 409, description = "Map changed concurrently", body = MapsErrorResponse),
        (status = 503, description = "Maps service is unavailable", body = MapsErrorResponse)
    )
)]
pub async fn delete_file(
    authorized: AuthorizedMaps,
    MapsServiceHandle { service, .. }: MapsServiceHandle,
    query: Result<Query<MapFilePathQuery>, QueryRejection>,
) -> Result<Json<MapFileMutationResponse>, MapsHttpError> {
    let Query(query) = query.map_err(|_| MapsHttpError::BadRequest)?;
    let path = parse_map_path(&query.path)?;
    let event = service.delete(request_context(authorized), path).await?;
    Ok(Json(event.into()))
}

#[utoipa::path(
    patch,
    path = "/files/rename",
    tag = TAG,
    security(("bearerAuth" = [])),
    request_body(content = RenameMapFileRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Map file renamed or toggled between .map and .map.off", body = MapFileMutationResponse),
        (status = 400, description = "Malformed, unsafe or unsupported map path", body = MapsErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = MapsErrorResponse),
        (status = 403, description = "Developer or mapper role is required", body = MapsErrorResponse),
        (status = 404, description = "Source map does not exist", body = MapsErrorResponse),
        (status = 409, description = "Destination exists, source changed or paths are equal", body = MapsErrorResponse),
        (status = 503, description = "Maps service is unavailable", body = MapsErrorResponse)
    )
)]
pub async fn rename_file(
    authorized: AuthorizedMaps,
    MapsServiceHandle { service, .. }: MapsServiceHandle,
    payload: Result<Json<RenameMapFileRequest>, JsonRejection>,
) -> Result<Json<MapFileMutationResponse>, MapsHttpError> {
    let Json(payload) = payload.map_err(|_| MapsHttpError::BadRequest)?;
    let source = parse_map_path(&payload.source)?;
    let destination = parse_map_path(&payload.destination)?;
    let event = service
        .rename(request_context(authorized), source, destination)
        .await?;
    Ok(Json(event.into()))
}

fn request_context(authorized: AuthorizedMaps) -> MapsRequestContext {
    let (principal, access) = authorized.into_parts();
    let actor = MutationActor::new(
        principal.user.id.to_string(),
        Some(principal.session_id.as_str().to_owned()),
    )
    .expect("authenticated principal always produces a valid mutation actor");
    MapsRequestContext::new(access, actor)
}

fn parse_map_path(value: &str) -> Result<MapFilePath, MapsHttpError> {
    let path = RelativeStoragePath::new(value).map_err(|_| MapsHttpError::BadRequest)?;
    MapFilePath::new(path).map_err(|_| MapsHttpError::BadRequest)
}

async fn multipart_batch(
    request: Request,
    limits: MultipartUploadLimits,
) -> Result<MapUploadBatch, MapsHttpError> {
    let parts = collect_multipart_upload(request, limits)
        .await
        .map_err(map_multipart_upload_error)?
        .into_parts();
    let mut uploads = Vec::with_capacity(parts.len());

    for part in parts {
        if part.name() != "files" {
            return Err(MapsHttpError::BadRequest);
        }
        let file_name = part.file_name().ok_or(MapsHttpError::BadRequest)?;
        let path = parse_map_path(file_name)?;
        uploads.push(MapUpload::new(path, part.into_bytes()));
    }

    MapUploadBatch::new(uploads).map_err(Into::into)
}

fn map_multipart_upload_error(error: MultipartUploadError) -> MapsHttpError {
    if error.is_too_large() {
        MapsHttpError::ContentTooLarge
    } else {
        MapsHttpError::BadRequest
    }
}

fn stream_response(file: OpenedMapFile) -> Result<Response, MapsHttpError> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/xml"))
        .header(
            CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("inline; filename=\"{}\"", file.file_name))
                .map_err(|_| MapsHttpError::Unavailable)?,
        )
        .header(CONTENT_LENGTH, file.content_length)
        .body(Body::from_stream(ReaderStream::new(file.reader)))
        .map_err(|_| MapsHttpError::Unavailable)
}

#[derive(Debug, Clone, Copy)]
pub enum MapsHttpError {
    BadRequest,
    NotFound,
    Conflict,
    ContentTooLarge,
    Unavailable,
}

impl From<InvalidMapUploadBatch> for MapsHttpError {
    fn from(_: InvalidMapUploadBatch) -> Self {
        Self::BadRequest
    }
}

impl From<MapsFileServiceError> for MapsHttpError {
    fn from(error: MapsFileServiceError) -> Self {
        match error {
            MapsFileServiceError::NotFound => Self::NotFound,
            MapsFileServiceError::AlreadyExists | MapsFileServiceError::Conflict => Self::Conflict,
            MapsFileServiceError::ContentTooLarge => Self::ContentTooLarge,
            MapsFileServiceError::Unavailable | MapsFileServiceError::Stream(_) => {
                Self::Unavailable
            }
        }
    }
}

impl IntoResponse for MapsHttpError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            Self::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            Self::Conflict => (StatusCode::CONFLICT, "CONFLICT"),
            Self::ContentTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "CONTENT_TOO_LARGE"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
        };
        (status, Json(MapsErrorResponse { code })).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_application_errors_to_stable_http_statuses() {
        let cases = [
            (MapsHttpError::BadRequest, StatusCode::BAD_REQUEST),
            (MapsHttpError::NotFound, StatusCode::NOT_FOUND),
            (MapsHttpError::Conflict, StatusCode::CONFLICT),
            (
                MapsHttpError::ContentTooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (MapsHttpError::Unavailable, StatusCode::SERVICE_UNAVAILABLE),
        ];

        for (error, expected) in cases {
            assert_eq!(error.into_response().status(), expected);
        }
    }

    #[test]
    fn accepts_only_safe_map_paths() {
        for path in ["race.map", "city/race.map.off", "CITY/RACE.MAP"] {
            assert!(parse_map_path(path).is_ok());
        }
        for path in [
            "",
            "../race.map",
            "C:\\race.map",
            "race.xml",
            "race.map.bak",
        ] {
            assert!(matches!(
                parse_map_path(path),
                Err(MapsHttpError::BadRequest)
            ));
        }
    }
}
