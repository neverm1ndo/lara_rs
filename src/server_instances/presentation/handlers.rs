use axum::{
    Json,
    extract::{Path, rejection::PathRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::{
    auth::presentation::extractors::CurrentSession,
    server_instances::{
        application::{
            manifest::ManifestSubject,
            runtime_state::{GetRuntimeStateError, RuntimeStateSubject},
        },
        domain::ServerInstanceId,
        presentation::{
            dto::{InstanceManifestResponse, RuntimeStateResponse, ServerInstanceErrorResponse},
            state::{InstanceManifestHandle, RuntimeStateHandle},
        },
    },
};

const TAG: &str = "Server instances";
const PRIVATE_REVALIDATION: HeaderValue = HeaderValue::from_static("private, no-cache");

#[utoipa::path(
    get,
    path = "/server-instances",
    tag = TAG,
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Effective server-instance capability manifest", body = InstanceManifestResponse),
        (status = 304, description = "Manifest has not changed"),
        (status = 401, description = "Bearer token or session is invalid or expired", body = String, content_type = "text/plain"),
        (status = 503, description = "Authentication dependency is unavailable", body = String, content_type = "text/plain")
    )
)]
pub async fn get_manifest(
    CurrentSession(principal): CurrentSession,
    InstanceManifestHandle(service): InstanceManifestHandle,
    headers: HeaderMap,
) -> Response {
    let subject = ManifestSubject::new(principal.user.main_group, principal.user.permissions);
    let manifest = service.get(&subject);
    let etag = format!("\"{}\"", manifest.revision);

    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|candidate| candidate.trim() == etag))
    {
        return response_with_cache_headers(StatusCode::NOT_MODIFIED.into_response(), &etag);
    }

    response_with_cache_headers(
        Json(InstanceManifestResponse::from(manifest)).into_response(),
        &etag,
    )
}

#[utoipa::path(
    get,
    path = "/server-instances/{instance_id}/state",
    tag = TAG,
    security(("bearerAuth" = [])),
    params(("instance_id" = String, Path, description = "Stable server-instance identifier")),
    responses(
        (status = 200, description = "Latest normalized runtime-state snapshot", body = RuntimeStateResponse),
        (status = 400, description = "Instance identifier is malformed", body = ServerInstanceErrorResponse),
        (status = 401, description = "Bearer token or session is invalid or expired", body = String, content_type = "text/plain"),
        (status = 403, description = "Developer role is required", body = ServerInstanceErrorResponse),
        (status = 404, description = "Server instance does not exist", body = ServerInstanceErrorResponse),
        (status = 503, description = "Authentication or runtime-state dependency is unavailable", body = ServerInstanceErrorResponse)
    )
)]
pub async fn get_runtime_state(
    CurrentSession(principal): CurrentSession,
    RuntimeStateHandle(service): RuntimeStateHandle,
    instance_id: Result<Path<String>, PathRejection>,
) -> Result<Response, ServerInstanceHttpError> {
    let Path(instance_id) = instance_id.map_err(|_| ServerInstanceHttpError::BadRequest)?;
    let instance_id =
        ServerInstanceId::new(instance_id).map_err(|_| ServerInstanceHttpError::BadRequest)?;
    let subject = RuntimeStateSubject::new(principal.user.main_group, principal.user.permissions);
    let state = service.get(&subject, &instance_id)?;
    let mut response = Json(RuntimeStateResponse::from(state)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerInstanceHttpError {
    BadRequest,
    Forbidden,
    NotFound,
    Unavailable,
}

impl From<GetRuntimeStateError> for ServerInstanceHttpError {
    fn from(error: GetRuntimeStateError) -> Self {
        match error {
            GetRuntimeStateError::Forbidden => Self::Forbidden,
            GetRuntimeStateError::NotFound => Self::NotFound,
            GetRuntimeStateError::Unavailable => Self::Unavailable,
        }
    }
}

impl IntoResponse for ServerInstanceHttpError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "INVALID_INSTANCE_ID"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "DEVELOPER_ROLE_REQUIRED"),
            Self::NotFound => (StatusCode::NOT_FOUND, "INSTANCE_NOT_FOUND"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
        };
        (status, Json(ServerInstanceErrorResponse { code })).into_response()
    }
}

fn response_with_cache_headers(mut response: Response, etag: &str) -> Response {
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(etag).expect("SHA-256 ETag is always a valid header value"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, PRIVATE_REVALIDATION);
    response
}
