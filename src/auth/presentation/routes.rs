use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    extractors::JwtExtractorState,
    handlers, mfa_handlers,
    state::{LoginState, MfaState},
};

/// Mount this router under `/auth` in the application's root router.
pub fn router<S>() -> OpenApiRouter<S>
where
    S: JwtExtractorState + LoginState + Clone + Send + Sync + 'static,
{
    OpenApiRouter::new()
        .routes(routes!(handlers::login))
        .routes(routes!(handlers::get_session))
}

/// MFA-aware replacement for `router`, activated by bootstrap once all MFA
/// adapters have been constructed.
#[allow(dead_code)]
pub fn mfa_router<S>() -> OpenApiRouter<S>
where
    S: JwtExtractorState + MfaState + Clone + Send + Sync + 'static,
{
    OpenApiRouter::new()
        .routes(routes!(mfa_handlers::begin_login))
        .routes(routes!(mfa_handlers::complete_login))
        .routes(routes!(handlers::get_session))
        .routes(routes!(mfa_handlers::status))
        .routes(routes!(mfa_handlers::begin_enrollment))
        .routes(routes!(mfa_handlers::confirm_enrollment))
        .routes(routes!(mfa_handlers::disable))
        .routes(routes!(mfa_handlers::regenerate_recovery_codes))
}
