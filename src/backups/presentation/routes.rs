use utoipa_axum::{router::OpenApiRouter, routes};

use super::{handlers, state::BackupsState};

/// Mount this router under `/backups`.
pub fn router<S>() -> OpenApiRouter<S>
where
    S: BackupsState + Clone + Send + Sync + 'static,
{
    OpenApiRouter::new()
        .routes(routes!(handlers::list_backups))
        .routes(routes!(handlers::download_backup, handlers::delete_backup))
        .routes(routes!(handlers::restore_backup))
}
