use std::{collections::BTreeMap, io, path::PathBuf};

use crate::{
    configuration::application::{
        mutation_log::ConfigurationFileEvidence,
        mutation_review::{ConfigurationEvidenceReader, EvidenceFuture},
    },
    shared::file_storage::{
        local::{FileStorageLimits, LocalFileStorage, LocalFileStorageError},
        path::RelativeStoragePath,
    },
};

pub struct LocalConfigurationEvidenceReader {
    roots: BTreeMap<String, PathBuf>,
    limits: FileStorageLimits,
}
impl LocalConfigurationEvidenceReader {
    pub fn new(roots: BTreeMap<String, PathBuf>, limits: FileStorageLimits) -> Self {
        Self { roots, limits }
    }
}

impl ConfigurationEvidenceReader for LocalConfigurationEvidenceReader {
    fn observe<'a>(&'a self, instance_id: &'a str, path: &'a str) -> EvidenceFuture<'a> {
        Box::pin(async move {
            let root = match self.roots.get(instance_id) {
                Some(root) => root,
                None => {
                    return ConfigurationFileEvidence::Unavailable(
                        "instance root is not registered".into(),
                    );
                }
            };
            let path = match RelativeStoragePath::new(path) {
                Ok(path) if !path.is_root() => path,
                _ => return ConfigurationFileEvidence::Unavailable("invalid recorded path".into()),
            };
            let storage = match LocalFileStorage::open(root, self.limits).await {
                Ok(storage) => storage,
                Err(error) => return ConfigurationFileEvidence::Unavailable(error.to_string()),
            };
            match storage.file_revision(&path).await {
                Ok(revision) => match revision.content_hash() {
                    Some(hash) => ConfigurationFileEvidence::Hash(hash.to_string()),
                    None => {
                        ConfigurationFileEvidence::Unavailable("content hash is unavailable".into())
                    }
                },
                Err(LocalFileStorageError::Io(error))
                    if error.kind() == io::ErrorKind::NotFound =>
                {
                    ConfigurationFileEvidence::Absent
                }
                Err(error) => ConfigurationFileEvidence::Unavailable(error.to_string()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn observes_only_the_requested_instance_root() {
        let root =
            std::env::temp_dir().join(format!("lara-review-evidence-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("server.cfg"), b"contents").unwrap();
        let reader = LocalConfigurationEvidenceReader::new(
            BTreeMap::from([
                ("test".into(), root.clone()),
                ("offline".into(), root.join("missing")),
            ]),
            FileStorageLimits::new(8, 100, 1024).unwrap(),
        );
        assert!(matches!(
            reader.observe("test", "server.cfg").await,
            ConfigurationFileEvidence::Hash(_)
        ));
        assert_eq!(
            reader.observe("test", "absent.cfg").await,
            ConfigurationFileEvidence::Absent
        );
        assert!(matches!(
            reader.observe("offline", "server.cfg").await,
            ConfigurationFileEvidence::Unavailable(_)
        ));
        std::fs::remove_dir_all(root).unwrap();
    }
}
