use std::sync::Arc;

use crate::auth::{
    application::{authenticate_jwt::AuthenticateBearerToken, login::Login},
    presentation::{extractors::JwtExtractorState, state::LoginState},
};
use crate::{
    configuration::presentation::authorization::ConfigurationAuthorizationState,
    shared::file_storage::path::RelativeStoragePath,
};

#[derive(Clone)]
pub struct AppState {
    jwt_authenticator: Arc<dyn AuthenticateBearerToken>,
    login_service: Arc<dyn Login>,
    configurator_directory: RelativeStoragePath,
}

impl AppState {
    pub fn new(
        authenticator: impl AuthenticateBearerToken + 'static,
        login_service: impl Login + 'static,
        configurator_directory: RelativeStoragePath,
    ) -> Self {
        Self {
            jwt_authenticator: Arc::new(authenticator),
            login_service: Arc::new(login_service),
            configurator_directory,
        }
    }
}

impl LoginState for AppState {
    fn login_service(&self) -> Arc<dyn Login> {
        Arc::clone(&self.login_service)
    }
}

impl JwtExtractorState for AppState {
    fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
        Arc::clone(&self.jwt_authenticator)
    }
}

impl ConfigurationAuthorizationState for AppState {
    fn configurator_directory(&self) -> &RelativeStoragePath {
        &self.configurator_directory
    }
}
