use utoipa_axum::{router::OpenApiRouter, routes};

use super::{handlers, state::MapsState};

/// Mount this router under `/maps`.
pub fn router<S>() -> OpenApiRouter<S>
where
    S: MapsState + Clone + Send + Sync + 'static,
{
    OpenApiRouter::new()
        .routes(routes!(handlers::get_tree))
        .routes(routes!(
            handlers::read_file,
            handlers::create_files,
            handlers::overwrite_files,
            handlers::delete_file
        ))
        .routes(routes!(handlers::rename_file))
}
