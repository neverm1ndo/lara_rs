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
        application::{
            lifecycle_operations::LifecycleOperationRepositoryError,
            lifecycle_service::{
                LifecycleCommand, LifecycleCommandDisposition, LifecycleOperationServiceError,
                LifecycleSubject,
            },
            manifest::ManifestSubject,
            runtime_state::{GetRuntimeStateError, RuntimeStateSubject},
        },
        domain::{IdempotencyKey, LifecycleActorId, LifecycleOperationId, ServerInstanceId},
        presentation::{
            dto::{
                CreateLifecycleOperationRequest, InstanceManifestResponse,
                LifecycleOperationListParameters, LifecycleOperationListResponse,
                LifecycleOperationResponse, RuntimeStateResponse, ServerInstanceErrorResponse,
            },
            state::{InstanceManifestHandle, LifecycleOperationHandle, RuntimeStateHandle},
        },
    },
};

const TAG: &str = "Server instances";
const PRIVATE_REVALIDATION: HeaderValue = HeaderValue::from_static("private, no-cache");
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

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

#[utoipa::path(
    post,
    path = "/server-instances/{instance_id}/operations",
    tag = TAG,
    security(("bearerAuth" = [])),
    params(
        ("instance_id" = String, Path, description = "Stable server-instance identifier"),
        ("Idempotency-Key" = String, Header, description = "Unique key containing 1 to 128 visible ASCII characters")
    ),
    request_body = CreateLifecycleOperationRequest,
    responses(
        (status = 202, description = "Lifecycle operation accepted or replayed", body = LifecycleOperationResponse),
        (status = 400, description = "Request, identifier or idempotency key is invalid", body = ServerInstanceErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = String, content_type = "text/plain"),
        (status = 403, description = "Developer role is required", body = ServerInstanceErrorResponse),
        (status = 404, description = "Server instance does not exist", body = ServerInstanceErrorResponse),
        (status = 409, description = "Idempotency key or active operation conflicts", body = ServerInstanceErrorResponse),
        (status = 503, description = "Lifecycle dependency is unavailable", body = ServerInstanceErrorResponse)
    )
)]
pub async fn create_lifecycle_operation(
    CurrentSession(principal): CurrentSession,
    LifecycleOperationHandle(service): LifecycleOperationHandle,
    headers: HeaderMap,
    instance_id: Result<Path<String>, PathRejection>,
    payload: Result<Json<CreateLifecycleOperationRequest>, JsonRejection>,
) -> Result<Response, ServerInstanceHttpError> {
    let instance_id = parse_instance_id(instance_id)?;
    let idempotency_key = parse_idempotency_key(&headers)?;
    let Json(payload) = payload.map_err(|_| ServerInstanceHttpError::BadRequest)?;
    let result = service
        .request(
            &lifecycle_subject(principal)?,
            LifecycleCommand {
                instance_id: instance_id.clone(),
                action: payload.action.into(),
                idempotency_key,
            },
        )
        .await?;
    let location = format!(
        "/server-instances/{instance_id}/operations/{}",
        result.operation.id()
    );
    let mut response = (
        StatusCode::ACCEPTED,
        Json(LifecycleOperationResponse::from(&result.operation)),
    )
        .into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&location).map_err(|_| ServerInstanceHttpError::Unavailable)?,
    );
    response.headers_mut().insert(
        "idempotency-replayed",
        HeaderValue::from_static(match result.disposition {
            LifecycleCommandDisposition::Created => "false",
            LifecycleCommandDisposition::Replayed => "true",
        }),
    );
    no_store(&mut response);
    Ok(response)
}

#[utoipa::path(
    get,
    path = "/server-instances/{instance_id}/operations",
    tag = TAG,
    security(("bearerAuth" = [])),
    params(
        ("instance_id" = String, Path, description = "Stable server-instance identifier"),
        LifecycleOperationListParameters
    ),
    responses(
        (status = 200, description = "Lifecycle operations ordered newest first", body = LifecycleOperationListResponse),
        (status = 400, description = "Identifier, cursor or page size is invalid", body = ServerInstanceErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = String, content_type = "text/plain"),
        (status = 403, description = "Developer role is required", body = ServerInstanceErrorResponse),
        (status = 404, description = "Server instance does not exist", body = ServerInstanceErrorResponse),
        (status = 503, description = "Lifecycle repository is unavailable", body = ServerInstanceErrorResponse)
    )
)]
pub async fn list_lifecycle_operations(
    CurrentSession(principal): CurrentSession,
    LifecycleOperationHandle(service): LifecycleOperationHandle,
    instance_id: Result<Path<String>, PathRejection>,
    query: Result<Query<LifecycleOperationListParameters>, QueryRejection>,
) -> Result<Response, ServerInstanceHttpError> {
    let instance_id = parse_instance_id(instance_id)?;
    let Query(parameters) = query.map_err(|_| ServerInstanceHttpError::BadRequest)?;
    let query = parameters
        .into_query()
        .map_err(|_| ServerInstanceHttpError::BadRequest)?;
    let operations = service
        .list(&lifecycle_subject(principal)?, &instance_id, query)
        .await?;
    let mut response =
        Json(LifecycleOperationListResponse::from_operations(&operations)).into_response();
    no_store(&mut response);
    Ok(response)
}

#[utoipa::path(
    get,
    path = "/server-instances/{instance_id}/operations/{operation_id}",
    tag = TAG,
    security(("bearerAuth" = [])),
    params(
        ("instance_id" = String, Path, description = "Stable server-instance identifier"),
        ("operation_id" = String, Path, description = "Lifecycle operation UUID")
    ),
    responses(
        (status = 200, description = "Durable lifecycle operation", body = LifecycleOperationResponse),
        (status = 400, description = "Instance or operation identifier is invalid", body = ServerInstanceErrorResponse),
        (status = 401, description = "Bearer token or session is invalid", body = String, content_type = "text/plain"),
        (status = 403, description = "Developer role is required", body = ServerInstanceErrorResponse),
        (status = 404, description = "Instance or operation does not exist", body = ServerInstanceErrorResponse),
        (status = 503, description = "Lifecycle repository is unavailable", body = ServerInstanceErrorResponse)
    )
)]
pub async fn get_lifecycle_operation(
    CurrentSession(principal): CurrentSession,
    LifecycleOperationHandle(service): LifecycleOperationHandle,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Response, ServerInstanceHttpError> {
    let Path((instance_id, operation_id)) =
        path.map_err(|_| ServerInstanceHttpError::BadRequest)?;
    let instance_id =
        ServerInstanceId::new(instance_id).map_err(|_| ServerInstanceHttpError::BadRequest)?;
    let operation_id = operation_id
        .parse::<LifecycleOperationId>()
        .map_err(|_| ServerInstanceHttpError::BadRequest)?;
    let operation = service
        .get(&lifecycle_subject(principal)?, &instance_id, operation_id)
        .await?;
    let mut response = Json(LifecycleOperationResponse::from(&operation)).into_response();
    no_store(&mut response);
    Ok(response)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerInstanceHttpError {
    BadRequest,
    Forbidden,
    InstanceNotFound,
    OperationNotFound,
    InstanceNotManaged,
    IdempotencyConflict,
    ActiveOperation,
    Conflict,
    Unavailable,
}

impl From<GetRuntimeStateError> for ServerInstanceHttpError {
    fn from(error: GetRuntimeStateError) -> Self {
        match error {
            GetRuntimeStateError::Forbidden => Self::Forbidden,
            GetRuntimeStateError::NotFound => Self::InstanceNotFound,
            GetRuntimeStateError::Unavailable => Self::Unavailable,
        }
    }
}

impl From<LifecycleOperationServiceError> for ServerInstanceHttpError {
    fn from(error: LifecycleOperationServiceError) -> Self {
        match error {
            LifecycleOperationServiceError::Forbidden => Self::Forbidden,
            LifecycleOperationServiceError::InstanceNotFound => Self::InstanceNotFound,
            LifecycleOperationServiceError::OperationNotFound => Self::OperationNotFound,
            LifecycleOperationServiceError::InstanceNotManaged => Self::InstanceNotManaged,
            LifecycleOperationServiceError::IdempotencyConflict { .. } => Self::IdempotencyConflict,
            LifecycleOperationServiceError::ActiveOperation { .. } => Self::ActiveOperation,
            LifecycleOperationServiceError::ConcurrentRequest
            | LifecycleOperationServiceError::Repository(
                LifecycleOperationRepositoryError::AlreadyExists
                | LifecycleOperationRepositoryError::ConcurrentModification,
            ) => Self::Conflict,
            LifecycleOperationServiceError::InvalidTimeout
            | LifecycleOperationServiceError::InvalidOperation(_)
            | LifecycleOperationServiceError::Repository(
                LifecycleOperationRepositoryError::InvalidData { .. }
                | LifecycleOperationRepositoryError::Unavailable { .. },
            )
            | LifecycleOperationServiceError::RuntimeState(_) => Self::Unavailable,
        }
    }
}

impl IntoResponse for ServerInstanceHttpError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "INVALID_INSTANCE_ID"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "DEVELOPER_ROLE_REQUIRED"),
            Self::InstanceNotFound => (StatusCode::NOT_FOUND, "INSTANCE_NOT_FOUND"),
            Self::OperationNotFound => (StatusCode::NOT_FOUND, "OPERATION_NOT_FOUND"),
            Self::InstanceNotManaged => (StatusCode::CONFLICT, "INSTANCE_NOT_MANAGED"),
            Self::IdempotencyConflict => (StatusCode::CONFLICT, "IDEMPOTENCY_KEY_CONFLICT"),
            Self::ActiveOperation => (StatusCode::CONFLICT, "ACTIVE_OPERATION_EXISTS"),
            Self::Conflict => (StatusCode::CONFLICT, "LIFECYCLE_OPERATION_CONFLICT"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
        };
        (status, Json(ServerInstanceErrorResponse { code })).into_response()
    }
}

fn parse_instance_id(
    value: Result<Path<String>, PathRejection>,
) -> Result<ServerInstanceId, ServerInstanceHttpError> {
    let Path(value) = value.map_err(|_| ServerInstanceHttpError::BadRequest)?;
    ServerInstanceId::new(value).map_err(|_| ServerInstanceHttpError::BadRequest)
}

fn parse_idempotency_key(headers: &HeaderMap) -> Result<IdempotencyKey, ServerInstanceHttpError> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
    let value = values.next().ok_or(ServerInstanceHttpError::BadRequest)?;
    if values.next().is_some() {
        return Err(ServerInstanceHttpError::BadRequest);
    }
    IdempotencyKey::new(
        value
            .to_str()
            .map_err(|_| ServerInstanceHttpError::BadRequest)?,
    )
    .map_err(|_| ServerInstanceHttpError::BadRequest)
}

fn lifecycle_subject(
    principal: crate::auth::domain::models::AuthenticatedPrincipal,
) -> Result<LifecycleSubject, ServerInstanceHttpError> {
    Ok(LifecycleSubject::new(
        LifecycleActorId::new(principal.user.id)
            .map_err(|_| ServerInstanceHttpError::Unavailable)?,
        principal.user.username,
        principal.user.main_group,
        principal.user.permissions,
    ))
}

fn no_store(response: &mut Response) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotency_header_must_be_single_and_valid() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            parse_idempotency_key(&headers),
            Err(ServerInstanceHttpError::BadRequest)
        );

        headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_static("request-1"),
        );
        assert_eq!(
            parse_idempotency_key(&headers).unwrap().as_str(),
            "request-1"
        );

        headers.append(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_static("request-2"),
        );
        assert_eq!(
            parse_idempotency_key(&headers),
            Err(ServerInstanceHttpError::BadRequest)
        );
    }

    #[test]
    fn lifecycle_errors_have_stable_http_categories() {
        for (error, status) in [
            (
                ServerInstanceHttpError::InstanceNotManaged,
                StatusCode::CONFLICT,
            ),
            (
                ServerInstanceHttpError::IdempotencyConflict,
                StatusCode::CONFLICT,
            ),
            (
                ServerInstanceHttpError::OperationNotFound,
                StatusCode::NOT_FOUND,
            ),
            (ServerInstanceHttpError::Forbidden, StatusCode::FORBIDDEN),
        ] {
            assert_eq!(error.into_response().status(), status);
        }
    }
}
