use crate::{
    configuration::application::instance_text::{
        ConfigurationEntityTag, InstanceConfigurationFuture, InstanceConfigurationMutation,
        InstanceConfigurationRequest,
    },
    shared::file_storage::path::RelativeStoragePath,
};

/// Opaque bytes. Artifact uploads never enter the text encoding pipeline.
pub struct ConfigurationArtifactContent(Vec<u8>);

impl ConfigurationArtifactContent {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

pub struct ConfigurationArtifactMetadata {
    pub content_length: u64,
    pub etag: ConfigurationEntityTag,
}

/// Application port for HEAD and conditional PUT of an existing allowlisted
/// binary file. Neither method manages the game process.
pub trait ConfigurationArtifactService: Send + Sync {
    fn metadata<'a>(
        &'a self,
        context: InstanceConfigurationRequest,
        path: RelativeStoragePath,
    ) -> InstanceConfigurationFuture<'a, ConfigurationArtifactMetadata>;

    fn replace<'a>(
        &'a self,
        context: InstanceConfigurationRequest,
        path: RelativeStoragePath,
        content: ConfigurationArtifactContent,
        expected: ConfigurationEntityTag,
    ) -> InstanceConfigurationFuture<'a, InstanceConfigurationMutation>;
}
