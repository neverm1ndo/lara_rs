use utoipa_axum::{router::OpenApiRouter, routes};

use super::{handlers, state::UserState};

/// Mount this router under `/user` in the application's root router.
pub fn router<S>() -> OpenApiRouter<S>
where
    S: UserState + Clone + Send + Sync + 'static,
{
    OpenApiRouter::new().routes(routes!(handlers::get_user))
}
