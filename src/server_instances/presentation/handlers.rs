use axum::{
    Json,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::{
    auth::presentation::extractors::CurrentSession,
    server_instances::{
        application::manifest::ManifestSubject,
        presentation::{dto::InstanceManifestResponse, state::InstanceManifestHandle},
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
