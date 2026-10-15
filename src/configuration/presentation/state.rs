use std::{convert::Infallible, sync::Arc};

use axum::{extract::FromRequestParts, http::request::Parts};
use encoding_rs::Encoding;

use super::authorization::ConfigurationAuthorizationState;
use crate::configuration::application::file_service::ConfigurationFileService;

pub trait ConfigurationState: ConfigurationAuthorizationState {
    fn configuration_file_service(&self) -> Arc<dyn ConfigurationFileService>;
    fn configuration_file_encoding(&self) -> &'static Encoding;
    fn configuration_file_upload_limit_bytes(&self) -> u64;
}

pub struct ConfigurationServiceHandle {
    pub service: Arc<dyn ConfigurationFileService>,
    pub encoding: &'static Encoding,
    pub upload_limit_bytes: u64,
}

impl<S> FromRequestParts<S> for ConfigurationServiceHandle
where
    S: ConfigurationState,
{
    type Rejection = Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self {
            service: state.configuration_file_service(),
            encoding: state.configuration_file_encoding(),
            upload_limit_bytes: state.configuration_file_upload_limit_bytes(),
        })
    }
}
