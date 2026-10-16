use std::{convert::Infallible, sync::Arc};

use axum::{extract::FromRequestParts, http::request::Parts};

use crate::{
    auth::presentation::extractors::JwtExtractorState,
    backups::application::lifecycle::BackupLifecycleService,
};

pub trait BackupsState: JwtExtractorState {
    fn backup_lifecycle_service(&self) -> Arc<BackupLifecycleService>;
}

pub struct BackupServiceHandle(pub Arc<BackupLifecycleService>);

impl<S> FromRequestParts<S> for BackupServiceHandle
where
    S: BackupsState,
{
    type Rejection = Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(state.backup_lifecycle_service()))
    }
}
