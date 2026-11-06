use std::{convert::Infallible, sync::Arc};

use axum::{extract::FromRequestParts, http::request::Parts};

use crate::{
    auth::presentation::extractors::JwtExtractorState,
    configuration::application::{
        artifact_service::ConfigurationArtifactService,
        instance_text::InstanceConfigurationTextService,
        mutation_service::ConfigurationMutationService, target::ConfigurationTargetResolver,
    },
};

pub trait InstanceConfigurationState: JwtExtractorState {
    fn configuration_target_resolver(&self) -> Arc<dyn ConfigurationTargetResolver>;
    fn instance_text_service(&self) -> Arc<dyn InstanceConfigurationTextService>;
    fn artifact_service(&self) -> Arc<dyn ConfigurationArtifactService>;
    fn configuration_mutation_service(&self) -> Arc<ConfigurationMutationService>;
}

pub struct InstanceConfigurationHandle {
    pub resolver: Arc<dyn ConfigurationTargetResolver>,
    pub text: Arc<dyn InstanceConfigurationTextService>,
    pub artifacts: Arc<dyn ConfigurationArtifactService>,
    pub mutations: Arc<ConfigurationMutationService>,
}

impl<S> FromRequestParts<S> for InstanceConfigurationHandle
where
    S: InstanceConfigurationState,
{
    type Rejection = Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self {
            resolver: state.configuration_target_resolver(),
            text: state.instance_text_service(),
            artifacts: state.artifact_service(),
            mutations: state.configuration_mutation_service(),
        })
    }
}
