use std::{convert::Infallible, sync::Arc};

use axum::{extract::FromRequestParts, http::request::Parts};

use crate::{
    auth::presentation::extractors::JwtExtractorState,
    server_instances::application::{
        manifest::InstanceManifestService, registry::InstanceRegistry,
    },
};

pub trait ServerInstancesState: JwtExtractorState {
    fn instance_registry(&self) -> Arc<dyn InstanceRegistry>;
}

pub struct InstanceManifestHandle(pub InstanceManifestService);

impl<S> FromRequestParts<S> for InstanceManifestHandle
where
    S: ServerInstancesState,
{
    type Rejection = Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(InstanceManifestService::new(
            state.instance_registry(),
        )))
    }
}
