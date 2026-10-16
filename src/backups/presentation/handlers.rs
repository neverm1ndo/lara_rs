use axum::{
    Json,
    body::Body,
    extract::{
        Path, Query,
        rejection::{PathRejection, QueryRejection},
    },
    http::{
        HeaderValue, StatusCode,
        header::{CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
};
use tokio_util::io::ReaderStream;

use super::{
    dto::{BackupListParameters, BackupListResponse, BackupsErrorResponse},
    state::BackupServiceHandle,
};
use crate::{
    auth::presentation::extractors::CurrentSession,
    backups::{
        application::{
            lifecycle::{BackupLifecycleError, OpenedBackupContent},
            ports::{BackupRepositoryError, BackupSnapshotStoreError},
        },
        domain::{BackupId, InvalidBackup},
    },
};

const TAG: &str = "Backups";

#[utoipa::path(
    get,
    path = "/list",
    tag = TAG,
    security(("bearerAuth" = [])),
    params(BackupListParameters),
    responses(
        (status = 200, description = "Backups ordered from newest to oldest", body = BackupListResponse),
        (status = 400, description = "Cursor or page size is invalid", body = BackupsErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = BackupsErrorResponse),
        (status = 503, description = "Backup service is unavailable", body = BackupsErrorResponse)
    )
)]
pub async fn list_backups(
    _session: CurrentSession,
    BackupServiceHandle(service): BackupServiceHandle,
    query: Result<Query<BackupListParameters>, QueryRejection>,
) -> Result<Json<BackupListResponse>, BackupsHttpError> {
    let Query(parameters) = query.map_err(|_| BackupsHttpError::BadRequest)?;
    let query = parameters
        .into_query()
        .map_err(|_| BackupsHttpError::BadRequest)?;
    let backups = service.list(query).await?;
    Ok(Json(BackupListResponse::from_backups(backups)))
}

#[utoipa::path(
    get,
    path = "/backup/{backup_id}",
    tag = TAG,
    security(("bearerAuth" = [])),
    params(("backup_id" = String, Path, description = "Backup UUID")),
    responses(
        (status = 200, description = "Original snapshot bytes without transcoding", body = String, content_type = "application/octet-stream"),
        (status = 400, description = "Backup identifier is invalid", body = BackupsErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = BackupsErrorResponse),
        (status = 404, description = "Backup does not exist", body = BackupsErrorResponse),
        (status = 409, description = "Backup is being modified", body = BackupsErrorResponse),
        (status = 503, description = "Backup service is unavailable", body = BackupsErrorResponse)
    )
)]
pub async fn download_backup(
    _session: CurrentSession,
    BackupServiceHandle(service): BackupServiceHandle,
    backup_id: Result<Path<String>, PathRejection>,
) -> Result<Response, BackupsHttpError> {
    let Path(backup_id) = backup_id.map_err(|_| BackupsHttpError::BadRequest)?;
    let opened = service.open(parse_id(&backup_id)?).await?;
    stream_response(opened)
}

#[utoipa::path(
    post,
    path = "/restore/{backup_id}",
    tag = TAG,
    security(("bearerAuth" = [])),
    params(("backup_id" = String, Path, description = "Backup UUID")),
    responses(
        (status = 204, description = "Snapshot restored"),
        (status = 400, description = "Backup identifier is invalid", body = BackupsErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = BackupsErrorResponse),
        (status = 404, description = "Backup does not exist", body = BackupsErrorResponse),
        (status = 409, description = "Backup is busy or was concurrently modified", body = BackupsErrorResponse),
        (status = 410, description = "Backup has expired", body = BackupsErrorResponse),
        (status = 503, description = "Backup or target storage is unavailable", body = BackupsErrorResponse)
    )
)]
pub async fn restore_backup(
    _session: CurrentSession,
    BackupServiceHandle(service): BackupServiceHandle,
    backup_id: Result<Path<String>, PathRejection>,
) -> Result<StatusCode, BackupsHttpError> {
    let Path(backup_id) = backup_id.map_err(|_| BackupsHttpError::BadRequest)?;
    service.restore(parse_id(&backup_id)?).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/backup/{backup_id}",
    tag = TAG,
    security(("bearerAuth" = [])),
    params(("backup_id" = String, Path, description = "Backup UUID")),
    responses(
        (status = 204, description = "Backup snapshot and metadata deleted"),
        (status = 400, description = "Backup identifier is invalid", body = BackupsErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = BackupsErrorResponse),
        (status = 404, description = "Backup does not exist", body = BackupsErrorResponse),
        (status = 409, description = "Backup is busy or was concurrently modified", body = BackupsErrorResponse),
        (status = 503, description = "Backup service is unavailable", body = BackupsErrorResponse)
    )
)]
pub async fn delete_backup(
    _session: CurrentSession,
    BackupServiceHandle(service): BackupServiceHandle,
    backup_id: Result<Path<String>, PathRejection>,
) -> Result<StatusCode, BackupsHttpError> {
    let Path(backup_id) = backup_id.map_err(|_| BackupsHttpError::BadRequest)?;
    service.remove(parse_id(&backup_id)?).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn parse_id(value: &str) -> Result<BackupId, BackupsHttpError> {
    value.parse().map_err(|_| BackupsHttpError::BadRequest)
}

fn stream_response(opened: OpenedBackupContent) -> Result<Response, BackupsHttpError> {
    let filename = opened.backup.id().to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, opened.content_length)
        .header(
            CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
                .map_err(|_| BackupsHttpError::Unavailable)?,
        )
        .body(Body::from_stream(ReaderStream::new(opened.reader)))
        .map_err(|_| BackupsHttpError::Unavailable)
}

#[derive(Debug, Clone, Copy)]
pub enum BackupsHttpError {
    BadRequest,
    NotFound,
    Conflict,
    Gone,
    Unavailable,
}

impl From<BackupLifecycleError> for BackupsHttpError {
    fn from(error: BackupLifecycleError) -> Self {
        match error {
            BackupLifecycleError::NotFound => Self::NotFound,
            BackupLifecycleError::UnavailableState
            | BackupLifecycleError::Repository(BackupRepositoryError::ConcurrentModification)
            | BackupLifecycleError::Domain(InvalidBackup::StateTransition) => Self::Conflict,
            BackupLifecycleError::Expired
            | BackupLifecycleError::Domain(InvalidBackup::Expired) => Self::Gone,
            BackupLifecycleError::TimeOverflow
            | BackupLifecycleError::SnapshotLengthMismatch
            | BackupLifecycleError::SnapshotTooLarge
            | BackupLifecycleError::SnapshotRead(_)
            | BackupLifecycleError::Repository(_)
            | BackupLifecycleError::Snapshot(
                BackupSnapshotStoreError::NotFound
                | BackupSnapshotStoreError::IntegrityMismatch
                | BackupSnapshotStoreError::AlreadyExists
                | BackupSnapshotStoreError::Unavailable { .. },
            )
            | BackupLifecycleError::Restore(_)
            | BackupLifecycleError::Domain(_) => Self::Unavailable,
        }
    }
}

impl IntoResponse for BackupsHttpError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            Self::NotFound => (StatusCode::NOT_FOUND, "BACKUP_NOT_FOUND"),
            Self::Conflict => (StatusCode::CONFLICT, "BACKUP_CONFLICT"),
            Self::Gone => (StatusCode::GONE, "BACKUP_EXPIRED"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
        };
        (status, Json(BackupsErrorResponse { code })).into_response()
    }
}
