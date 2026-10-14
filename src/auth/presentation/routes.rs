use utoipa_axum::{router::OpenApiRouter, routes};

use super::{extractors::JwtExtractorState, handlers, state::LoginState};

/// Mount this router under `/auth` in the application's root router.
pub fn router<S>() -> OpenApiRouter<S>
where
    S: JwtExtractorState + LoginState + Clone + Send + Sync + 'static,
{
    OpenApiRouter::new()
        .routes(routes!(handlers::login))
        .routes(routes!(handlers::get_session))
}
