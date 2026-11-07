use axum::{
    Json,
    extract::{
        Path, Query,
        rejection::{JsonRejection, PathRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::{
    auth::presentation::extractors::CurrentSession,
    server_instances::{
        application::incident_management::{ManagementError, ReviewAction},
        domain::{IdempotencyKey, IncidentId, ServerInstanceId},
        presentation::{
            incident_dto::{
                ChangeIncidentReviewRequest, ChangeIncidentReviewResponse, IncidentErrorResponse,
                IncidentListParameters, IncidentListResponse, IncidentResponse, ReviewStateRequest,
            },
            state::IncidentManagementHandle,
        },
    },
};

const TAG: &str = "Server instances";

#[utoipa::path(get, path = "/server-instances/{instance_id}/incidents", tag = TAG,
    security(("bearerAuth" = [])),
    params(("instance_id" = String, Path, description = "Server instance ID"), IncidentListParameters),
    responses(
        (status = 200, description = "Incidents in stable newest-first order", body = IncidentListResponse),
        (status = 400, description = "Invalid filter, cursor or page size", body = IncidentErrorResponse),
        (status = 401, description = "Invalid session", body = String, content_type = "text/plain"),
        (status = 403, description = "Developer role required for primary", body = IncidentErrorResponse),
        (status = 404, description = "Instance not found or hidden", body = IncidentErrorResponse),
        (status = 503, description = "Incident store unavailable", body = IncidentErrorResponse)
    )
)]
pub async fn list_incidents(
    CurrentSession(principal): CurrentSession,
    IncidentManagementHandle(service): IncidentManagementHandle,
    path: Result<Path<String>, PathRejection>,
    query: Result<Query<IncidentListParameters>, QueryRejection>,
) -> Result<Response, IncidentHttpError> {
    let instance = parse_instance(path)?;
    let Query(query) = query.map_err(|_| IncidentHttpError::BadRequest)?;
    let request = query
        .into_request()
        .map_err(|_| IncidentHttpError::BadRequest)?;
    let page = service
        .list(
            principal.user.main_group,
            &principal.user.permissions,
            &instance,
            request,
        )
        .await?;
    Ok(no_store(
        Json(IncidentListResponse::from(page)).into_response(),
    ))
}

#[utoipa::path(get, path = "/server-instances/{instance_id}/incidents/{incident_id}", tag = TAG,
    security(("bearerAuth" = [])),
    params(("instance_id" = String, Path, description = "Server instance ID"), ("incident_id" = String, Path, description = "Incident UUID")),
    responses(
        (status = 200, description = "Incident detail with review history", body = IncidentResponse),
        (status = 400, description = "Malformed identifier", body = IncidentErrorResponse),
        (status = 401, description = "Invalid session", body = String, content_type = "text/plain"),
        (status = 403, description = "Developer role required for primary", body = IncidentErrorResponse),
        (status = 404, description = "Incident or instance not found", body = IncidentErrorResponse),
        (status = 503, description = "Incident store unavailable", body = IncidentErrorResponse)
    )
)]
pub async fn get_incident(
    CurrentSession(principal): CurrentSession,
    IncidentManagementHandle(service): IncidentManagementHandle,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Response, IncidentHttpError> {
    let (instance, incident) = parse_ids(path)?;
    let incident = service
        .get(
            principal.user.main_group,
            &principal.user.permissions,
            &instance,
            incident,
        )
        .await?;
    let mut response = no_store(Json(IncidentResponse::from(&incident)).into_response());
    response
        .headers_mut()
        .insert(header::ETAG, etag(incident.version())?);
    Ok(response)
}

#[utoipa::path(patch, path = "/server-instances/{instance_id}/incidents/{incident_id}/review", tag = TAG,
    security(("bearerAuth" = [])),
    params(("instance_id" = String, Path, description = "Server instance ID"), ("incident_id" = String, Path, description = "Incident UUID"), ("Idempotency-Key" = String, Header, description = "Unique review request key"), ("If-Match" = String, Header, description = "Strong incident version ETag")),
    request_body = ChangeIncidentReviewRequest,
    responses(
        (status = 200, description = "Review state changed or idempotently replayed", body = ChangeIncidentReviewResponse),
        (status = 400, description = "Malformed request", body = IncidentErrorResponse),
        (status = 401, description = "Invalid session", body = String, content_type = "text/plain"),
        (status = 403, description = "Developer role required for primary", body = IncidentErrorResponse),
        (status = 404, description = "Incident or instance not found", body = IncidentErrorResponse),
        (status = 409, description = "Review transition or idempotency key conflicts", body = IncidentErrorResponse),
        (status = 412, description = "Incident version changed", body = IncidentErrorResponse),
        (status = 428, description = "If-Match header required", body = IncidentErrorResponse),
        (status = 503, description = "Incident store unavailable", body = IncidentErrorResponse)
    )
)]
pub async fn change_review(
    CurrentSession(principal): CurrentSession,
    IncidentManagementHandle(service): IncidentManagementHandle,
    headers: HeaderMap,
    path: Result<Path<(String, String)>, PathRejection>,
    payload: Result<Json<ChangeIncidentReviewRequest>, JsonRejection>,
) -> Result<Response, IncidentHttpError> {
    let (instance, incident) = parse_ids(path)?;
    service.authorize(
        principal.user.main_group,
        &principal.user.permissions,
        &instance,
    )?;
    let key = single_header(&headers, "idempotency-key")?.ok_or(IncidentHttpError::BadRequest)?;
    let key = IdempotencyKey::new(key).map_err(|_| IncidentHttpError::BadRequest)?;
    let version = single_header(&headers, header::IF_MATCH.as_str())?
        .ok_or(IncidentHttpError::PreconditionRequired)?;
    let version = parse_etag(version)?;
    let Json(payload) = payload.map_err(|_| IncidentHttpError::BadRequest)?;
    let action = match payload.review_state {
        ReviewStateRequest::Acknowledged => ReviewAction::Acknowledge,
        ReviewStateRequest::Investigated => ReviewAction::Investigate,
    };
    let result = service
        .review(
            principal.user.main_group,
            &principal.user.permissions,
            &instance,
            incident,
            principal.user.id,
            key.as_str(),
            version,
            action,
            payload.note,
        )
        .await?;
    let mut response =
        no_store(Json(ChangeIncidentReviewResponse::from(result.clone())).into_response());
    response
        .headers_mut()
        .insert(header::ETAG, etag(result.version)?);
    Ok(response)
}

fn parse_instance(
    path: Result<Path<String>, PathRejection>,
) -> Result<ServerInstanceId, IncidentHttpError> {
    ServerInstanceId::new(path.map_err(|_| IncidentHttpError::BadRequest)?.0)
        .map_err(|_| IncidentHttpError::BadRequest)
}

fn parse_ids(
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<(ServerInstanceId, IncidentId), IncidentHttpError> {
    let Path((instance, incident)) = path.map_err(|_| IncidentHttpError::BadRequest)?;
    Ok((
        ServerInstanceId::new(instance).map_err(|_| IncidentHttpError::BadRequest)?,
        incident
            .parse()
            .map_err(|_| IncidentHttpError::BadRequest)?,
    ))
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, IncidentHttpError> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(IncidentHttpError::BadRequest);
    }
    first
        .map(|value| value.to_str().map_err(|_| IncidentHttpError::BadRequest))
        .transpose()
}

fn parse_etag(value: &str) -> Result<u64, IncidentHttpError> {
    if value.starts_with("W/") || !value.starts_with('"') || !value.ends_with('"') {
        return Err(IncidentHttpError::BadRequest);
    }
    let version = value[1..value.len() - 1]
        .parse::<u64>()
        .map_err(|_| IncidentHttpError::BadRequest)?;
    if value != format!("\"{version}\"") {
        return Err(IncidentHttpError::BadRequest);
    }
    Ok(version)
}

fn etag(version: u64) -> Result<HeaderValue, IncidentHttpError> {
    HeaderValue::from_str(&format!("\"{version}\"")).map_err(|_| IncidentHttpError::Unavailable)
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Debug)]
pub enum IncidentHttpError {
    BadRequest,
    PreconditionRequired,
    Forbidden,
    NotFound,
    Conflict,
    PreconditionFailed,
    Unavailable,
}

impl From<ManagementError> for IncidentHttpError {
    fn from(value: ManagementError) -> Self {
        match value {
            ManagementError::BadRequest => Self::BadRequest,
            ManagementError::Forbidden => Self::Forbidden,
            ManagementError::NotFound => Self::NotFound,
            ManagementError::Conflict => Self::Conflict,
            ManagementError::PreconditionFailed => Self::PreconditionFailed,
            ManagementError::Unavailable => Self::Unavailable,
        }
    }
}

impl IntoResponse for IncidentHttpError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            Self::PreconditionRequired => {
                (StatusCode::PRECONDITION_REQUIRED, "PRECONDITION_REQUIRED")
            }
            Self::Forbidden => (StatusCode::FORBIDDEN, "FORBIDDEN"),
            Self::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            Self::Conflict => (StatusCode::CONFLICT, "CONFLICT"),
            Self::PreconditionFailed => (StatusCode::PRECONDITION_FAILED, "PRECONDITION_FAILED"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
        };
        no_store((status, Json(IncidentErrorResponse { code })).into_response())
    }
}
