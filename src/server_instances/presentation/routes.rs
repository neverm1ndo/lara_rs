use utoipa_axum::{router::OpenApiRouter, routes};

use super::{handlers, state::ServerInstancesState};

/// This domain owns a root-level collection route, so the router is merged
/// directly into the application's root router rather than nested.
pub fn router<S>() -> OpenApiRouter<S>
where
    S: ServerInstancesState + Clone + Send + Sync + 'static,
{
    OpenApiRouter::new()
        .routes(routes!(handlers::get_manifest))
        .routes(routes!(handlers::get_runtime_state))
}
