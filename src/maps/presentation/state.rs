use std::{convert::Infallible, sync::Arc};

use axum::{extract::FromRequestParts, http::request::Parts};

use super::authorization::MapsAuthorizationState;
use crate::{
    maps::application::file_service::MapsFileService,
    shared::file_storage::upload::MultipartUploadLimits,
};

pub trait MapsState: MapsAuthorizationState {
    fn maps_file_service(&self) -> Arc<dyn MapsFileService>;
    fn maps_upload_limits(&self) -> MultipartUploadLimits;
}

pub struct MapsServiceHandle {
    pub service: Arc<dyn MapsFileService>,
    pub upload_limits: MultipartUploadLimits,
}

impl<S> FromRequestParts<S> for MapsServiceHandle
where
    S: MapsState,
{
    type Rejection = Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self {
            service: state.maps_file_service(),
            upload_limits: state.maps_upload_limits(),
        })
    }
}
