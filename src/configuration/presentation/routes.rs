use utoipa_axum::{router::OpenApiRouter, routes};

use super::{handlers, state::ConfigurationState};

/// Mount this router under `/configuration`.
pub fn router<S>() -> OpenApiRouter<S>
where
    S: ConfigurationState + Clone + Send + Sync + 'static,
{
    OpenApiRouter::new()
        .routes(routes!(handlers::get_tree))
        .routes(routes!(
            handlers::read_file,
            handlers::create_file,
            handlers::overwrite_file,
            handlers::delete_file
        ))
        .routes(routes!(handlers::rename_file))
}
