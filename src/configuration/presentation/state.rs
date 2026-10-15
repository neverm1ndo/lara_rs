use std::{convert::Infallible, sync::Arc};

use axum::{extract::FromRequestParts, http::request::Parts};

use super::authorization::ConfigurationAuthorizationState;
use crate::configuration::application::file_service::ConfigurationFileService;

pub trait ConfigurationState: ConfigurationAuthorizationState {
    fn configuration_file_service(&self) -> Arc<dyn ConfigurationFileService>;
}

pub struct ConfigurationServiceHandle(pub Arc<dyn ConfigurationFileService>);

impl<S> FromRequestParts<S> for ConfigurationServiceHandle
where
    S: ConfigurationState,
{
    type Rejection = Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(state.configuration_file_service()))
    }
}
