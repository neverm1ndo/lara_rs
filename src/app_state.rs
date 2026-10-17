use std::sync::Arc;

use crate::auth::{
    application::{
        authenticate_jwt::AuthenticateBearerToken,
        mfa::{login::MfaLogin, management::ManageMfa},
    },
    presentation::{extractors::JwtExtractorState, state::MfaState},
};
use crate::{
    backups::{application::lifecycle::BackupLifecycleService, presentation::state::BackupsState},
    configuration::presentation::authorization::ConfigurationAuthorizationState,
    maps::{application::file_service::MapsFileService, presentation::state::MapsState},
    shared::file_storage::{path::RelativeStoragePath, upload::MultipartUploadLimits},
    user::{application::get_user::GetUser, presentation::state::UserState},
};

#[derive(Clone)]
pub struct AppState {
    jwt_authenticator: Arc<dyn AuthenticateBearerToken>,
    mfa_login_service: Arc<dyn MfaLogin>,
    mfa_management_service: Arc<dyn ManageMfa>,
    get_user_service: Arc<dyn GetUser>,
    configurator_directory: RelativeStoragePath,
    maps_file_service: Arc<dyn MapsFileService>,
    maps_upload_limits: MultipartUploadLimits,
    backup_lifecycle_service: Arc<BackupLifecycleService>,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authenticator: impl AuthenticateBearerToken + 'static,
        mfa_login_service: impl MfaLogin + 'static,
        mfa_management_service: impl ManageMfa + 'static,
        get_user_service: impl GetUser + 'static,
        configurator_directory: RelativeStoragePath,
        maps_file_service: impl MapsFileService + 'static,
        maps_upload_limits: MultipartUploadLimits,
        backup_lifecycle_service: Arc<BackupLifecycleService>,
    ) -> Self {
        Self {
            jwt_authenticator: Arc::new(authenticator),
            mfa_login_service: Arc::new(mfa_login_service),
            mfa_management_service: Arc::new(mfa_management_service),
            get_user_service: Arc::new(get_user_service),
            configurator_directory,
            maps_file_service: Arc::new(maps_file_service),
            maps_upload_limits,
            backup_lifecycle_service,
        }
    }
}

impl UserState for AppState {
    fn get_user_service(&self) -> Arc<dyn GetUser> {
        Arc::clone(&self.get_user_service)
    }
}

impl BackupsState for AppState {
    fn backup_lifecycle_service(&self) -> Arc<BackupLifecycleService> {
        Arc::clone(&self.backup_lifecycle_service)
    }
}

impl MfaState for AppState {
    fn mfa_login_service(&self) -> Arc<dyn MfaLogin> {
        Arc::clone(&self.mfa_login_service)
    }

    fn mfa_management_service(&self) -> Arc<dyn ManageMfa> {
        Arc::clone(&self.mfa_management_service)
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

impl MapsState for AppState {
    fn maps_file_service(&self) -> Arc<dyn MapsFileService> {
        Arc::clone(&self.maps_file_service)
    }

    fn maps_upload_limits(&self) -> MultipartUploadLimits {
        self.maps_upload_limits
    }
}
