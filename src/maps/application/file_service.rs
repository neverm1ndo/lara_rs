use std::{future::Future, io, pin::Pin};

use chrono::{DateTime, Utc};
use thiserror::Error;
use tokio::io::AsyncRead;

use crate::{
    maps::domain::{
        InvalidMapFilePath, MapAccess, MapFileChanged, MapFileKind, MapFilePath, MapFilePolicy,
    },
    shared::file_storage::{mutation::MutationActor, path::RelativeStoragePath},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapsRequestContext {
    access: MapAccess,
    actor: MutationActor,
}

impl MapsRequestContext {
    pub fn new(access: MapAccess, actor: MutationActor) -> Self {
        Self { access, actor }
    }

    pub fn access(&self) -> MapAccess {
        self.access
    }

    pub fn actor(&self) -> &MutationActor {
        &self.actor
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapsTreeEntryKind {
    Directory,
    ActiveMap,
    DisabledMap,
}

impl From<MapFileKind> for MapsTreeEntryKind {
    fn from(kind: MapFileKind) -> Self {
        match kind {
            MapFileKind::Active => Self::ActiveMap,
            MapFileKind::Disabled => Self::DisabledMap,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapsTreeEntry {
    pub path: RelativeStoragePath,
    pub name: String,
    pub kind: MapsTreeEntryKind,
    pub size: Option<u64>,
    pub modified_at: Option<DateTime<Utc>>,
    pub children: Vec<MapsTreeEntry>,
}

/// An opaque map file stream. The backend deliberately does not parse XML or
/// transcode bytes; clients receive exactly what is stored on disk.
pub struct OpenedMapFile {
    pub reader: Pin<Box<dyn AsyncRead + Send>>,
    pub content_length: u64,
    pub file_name: String,
}

/// Opaque bytes supplied for one map file in a multipart batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapUpload {
    path: MapFilePath,
    content: Vec<u8>,
}

impl MapUpload {
    pub fn new(path: MapFilePath, content: Vec<u8>) -> Self {
        Self { path, content }
    }

    pub fn path(&self) -> &MapFilePath {
        &self.path
    }

    pub fn content(&self) -> &[u8] {
        &self.content
    }

    pub fn into_parts(self) -> (MapFilePath, Vec<u8>) {
        (self.path, self.content)
    }
}

/// A non-empty upload batch with case-insensitively unique destination paths.
/// Multipart count and byte limits are enforced at the HTTP boundary before
/// this application value is constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapUploadBatch(Vec<MapUpload>);

impl MapUploadBatch {
    pub fn new(uploads: Vec<MapUpload>) -> Result<Self, InvalidMapUploadBatch> {
        if uploads.is_empty() {
            return Err(InvalidMapUploadBatch::Empty);
        }

        MapFilePolicy
            .ensure_unique(uploads.iter().map(MapUpload::path))
            .map_err(InvalidMapUploadBatch::from)?;

        Ok(Self(uploads))
    }

    pub fn uploads(&self) -> &[MapUpload] {
        &self.0
    }

    pub fn into_uploads(self) -> Vec<MapUpload> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidMapUploadBatch {
    #[error("a map upload batch must contain at least one file")]
    Empty,
    #[error("map upload paths must be unique ignoring ASCII case")]
    DuplicatePath,
}

impl From<InvalidMapFilePath> for InvalidMapUploadBatch {
    fn from(error: InvalidMapFilePath) -> Self {
        match error {
            InvalidMapFilePath::DuplicatePath => Self::DuplicatePath,
            _ => unreachable!("uploads already contain validated map paths"),
        }
    }
}

pub type MapsServiceFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, MapsFileServiceError>> + Send + 'a>>;

/// Application boundary consumed by the maps HTTP handlers.
///
/// Create and overwrite remain distinct so the infrastructure layer can run
/// the correct pre-mutation backup flow without a check-then-write race.
pub trait MapsFileService: Send + Sync {
    fn tree<'a>(&'a self, context: MapsRequestContext)
    -> MapsServiceFuture<'a, Vec<MapsTreeEntry>>;

    fn open<'a>(
        &'a self,
        context: MapsRequestContext,
        path: MapFilePath,
    ) -> MapsServiceFuture<'a, OpenedMapFile>;

    fn create_many<'a>(
        &'a self,
        context: MapsRequestContext,
        batch: MapUploadBatch,
    ) -> MapsServiceFuture<'a, Vec<MapFileChanged>>;

    fn overwrite_many<'a>(
        &'a self,
        context: MapsRequestContext,
        batch: MapUploadBatch,
    ) -> MapsServiceFuture<'a, Vec<MapFileChanged>>;

    fn delete<'a>(
        &'a self,
        context: MapsRequestContext,
        path: MapFilePath,
    ) -> MapsServiceFuture<'a, MapFileChanged>;

    fn rename<'a>(
        &'a self,
        context: MapsRequestContext,
        source: MapFilePath,
        destination: MapFilePath,
    ) -> MapsServiceFuture<'a, MapFileChanged>;
}

#[derive(Debug, Error)]
pub enum MapsFileServiceError {
    #[error("map file was not found")]
    NotFound,
    #[error("map destination already exists")]
    AlreadyExists,
    #[error("map file changed concurrently")]
    Conflict,
    #[error("map content exceeds the allowed size")]
    ContentTooLarge,
    #[error("map file service is unavailable")]
    Unavailable,
    #[error("map stream failed")]
    Stream(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{shared::file_storage::path::RelativeStoragePath, shared::user_role::UserRole};

    fn upload(path: &str, content: Vec<u8>) -> MapUpload {
        MapUpload::new(
            MapFilePath::new(RelativeStoragePath::new(path).unwrap()).unwrap(),
            content,
        )
    }

    #[test]
    fn request_context_preserves_access_and_actor() {
        let access = MapAccess::authorize(UserRole::MAPPER, &[]).unwrap();
        let actor = MutationActor::new("42", Some("session-1".into())).unwrap();
        let context = MapsRequestContext::new(access, actor.clone());

        assert_eq!(context.access(), access);
        assert_eq!(context.actor(), &actor);
    }

    #[test]
    fn accepts_nested_active_and_disabled_maps_as_opaque_bytes() {
        let first_bytes = vec![0, 0xff, 0x98, b'<'];
        let second_bytes = b"<map />".to_vec();
        let batch = MapUploadBatch::new(vec![
            upload("city/race.map", first_bytes.clone()),
            upload("archive/race.map.off", second_bytes.clone()),
        ])
        .unwrap();

        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());
        assert_eq!(batch.uploads()[0].content(), first_bytes);
        assert_eq!(batch.uploads()[1].content(), second_bytes);

        let (path, bytes) = batch.into_uploads().remove(0).into_parts();
        assert_eq!(path.to_string(), "city/race.map");
        assert_eq!(bytes, first_bytes);
    }

    #[test]
    fn rejects_empty_and_case_insensitively_duplicate_batches() {
        assert_eq!(
            MapUploadBatch::new(vec![]),
            Err(InvalidMapUploadBatch::Empty)
        );
        assert_eq!(
            MapUploadBatch::new(vec![
                upload("city/Race.map", vec![1]),
                upload("CITY/race.MAP", vec![2]),
            ]),
            Err(InvalidMapUploadBatch::DuplicatePath)
        );
    }

    #[test]
    fn maps_file_kinds_to_tree_entry_kinds() {
        assert_eq!(
            MapsTreeEntryKind::from(MapFileKind::Active),
            MapsTreeEntryKind::ActiveMap
        );
        assert_eq!(
            MapsTreeEntryKind::from(MapFileKind::Disabled),
            MapsTreeEntryKind::DisabledMap
        );
    }
}
