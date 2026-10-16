use chrono::{DateTime, Utc};
use thiserror::Error;

use super::{InvalidMapFilePath, MapAccess, MapAccessLevel, MapFilePath};
use crate::shared::file_storage::{
    event::FileChanged,
    guard::BackupReceipt,
    mutation::{FileMutationKind, FileRevision, MutationActor, MutationId},
    path::RelativeStoragePath,
};

pub const MAPS_STORAGE_NAMESPACE: &str = "maps";
pub const MAP_FILE_CHANGED_EVENT_TYPE: &str = "maps.file-changed.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MapsEventId(MutationId);

impl MapsEventId {
    pub fn mutation_id(self) -> MutationId {
        self.0
    }
}

impl std::fmt::Display for MapsEventId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{MAP_FILE_CHANGED_EVENT_TYPE}:{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapFileChange {
    Created {
        path: MapFilePath,
    },
    Overwritten {
        path: MapFilePath,
    },
    Deleted {
        path: MapFilePath,
    },
    Renamed {
        source: MapFilePath,
        destination: MapFilePath,
    },
}

impl MapFileChange {
    pub fn source(&self) -> Option<&MapFilePath> {
        match self {
            Self::Created { .. } => None,
            Self::Overwritten { path } | Self::Deleted { path } => Some(path),
            Self::Renamed { source, .. } => Some(source),
        }
    }

    pub fn destination(&self) -> Option<&MapFilePath> {
        match self {
            Self::Deleted { .. } => None,
            Self::Created { path } | Self::Overwritten { path } => Some(path),
            Self::Renamed { destination, .. } => Some(destination),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapFileChanged {
    event_id: MapsEventId,
    actor: MutationActor,
    access_level: MapAccessLevel,
    occurred_at: DateTime<Utc>,
    change: MapFileChange,
    previous_revision: Option<FileRevision>,
    current_revision: Option<FileRevision>,
    backup_receipt: Option<BackupReceipt>,
}

impl MapFileChanged {
    /// Converts the generic storage event into a maps-domain event. Storage
    /// paths are relative to the configured maps capability root.
    pub fn from_storage(
        storage_event: &FileChanged,
        access: MapAccess,
    ) -> Result<Self, InvalidMapsDomainEvent> {
        if storage_event.namespace().as_str() != MAPS_STORAGE_NAMESPACE {
            return Err(InvalidMapsDomainEvent::UnexpectedNamespace);
        }

        let change = match storage_event.kind() {
            FileMutationKind::Create => MapFileChange::Created {
                path: map_path(valid_create(storage_event)?)?,
            },
            FileMutationKind::Overwrite => MapFileChange::Overwritten {
                path: map_path(valid_overwrite(storage_event)?)?,
            },
            FileMutationKind::Delete => MapFileChange::Deleted {
                path: map_path(valid_delete(storage_event)?)?,
            },
            FileMutationKind::Rename => {
                let (source, destination) = valid_rename(storage_event)?;
                MapFileChange::Renamed {
                    source: map_path(source)?,
                    destination: map_path(destination)?,
                }
            }
        };

        Ok(Self {
            event_id: MapsEventId(storage_event.mutation_id()),
            actor: storage_event.actor().clone(),
            access_level: access.level(),
            occurred_at: storage_event.occurred_at(),
            change,
            previous_revision: storage_event.previous_revision().cloned(),
            current_revision: storage_event.current_revision().cloned(),
            backup_receipt: storage_event.backup_receipt().cloned(),
        })
    }

    pub fn event_id(&self) -> MapsEventId {
        self.event_id
    }

    pub fn actor(&self) -> &MutationActor {
        &self.actor
    }

    pub fn access_level(&self) -> MapAccessLevel {
        self.access_level
    }

    pub fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }

    pub fn change(&self) -> &MapFileChange {
        &self.change
    }

    pub fn previous_revision(&self) -> Option<&FileRevision> {
        self.previous_revision.as_ref()
    }

    pub fn current_revision(&self) -> Option<&FileRevision> {
        self.current_revision.as_ref()
    }

    pub fn backup_receipt(&self) -> Option<&BackupReceipt> {
        self.backup_receipt.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapsDomainEvent {
    FileChanged(MapFileChanged),
}

impl MapsDomainEvent {
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::FileChanged(_) => MAP_FILE_CHANGED_EVENT_TYPE,
        }
    }

    pub fn event_id(&self) -> MapsEventId {
        match self {
            Self::FileChanged(event) => event.event_id(),
        }
    }

    pub fn occurred_at(&self) -> DateTime<Utc> {
        match self {
            Self::FileChanged(event) => event.occurred_at(),
        }
    }
}

impl From<MapFileChanged> for MapsDomainEvent {
    fn from(event: MapFileChanged) -> Self {
        Self::FileChanged(event)
    }
}

fn map_path(path: &RelativeStoragePath) -> Result<MapFilePath, InvalidMapsDomainEvent> {
    MapFilePath::new(path.clone()).map_err(Into::into)
}

fn valid_create(event: &FileChanged) -> Result<&RelativeStoragePath, InvalidMapsDomainEvent> {
    match (
        event.source(),
        event.destination(),
        event.previous_revision(),
        event.current_revision(),
    ) {
        (None, Some(destination), None, Some(_)) => Ok(destination),
        _ => Err(InvalidMapsDomainEvent::MalformedStorageEvent),
    }
}

fn valid_overwrite(event: &FileChanged) -> Result<&RelativeStoragePath, InvalidMapsDomainEvent> {
    match (
        event.source(),
        event.destination(),
        event.previous_revision(),
        event.current_revision(),
    ) {
        (Some(source), Some(destination), Some(_), Some(_)) if source == destination => Ok(source),
        _ => Err(InvalidMapsDomainEvent::MalformedStorageEvent),
    }
}

fn valid_delete(event: &FileChanged) -> Result<&RelativeStoragePath, InvalidMapsDomainEvent> {
    match (
        event.source(),
        event.destination(),
        event.previous_revision(),
        event.current_revision(),
    ) {
        (Some(source), None, Some(_), None) => Ok(source),
        _ => Err(InvalidMapsDomainEvent::MalformedStorageEvent),
    }
}

fn valid_rename(
    event: &FileChanged,
) -> Result<(&RelativeStoragePath, &RelativeStoragePath), InvalidMapsDomainEvent> {
    match (
        event.source(),
        event.destination(),
        event.previous_revision(),
        event.current_revision(),
    ) {
        (Some(source), Some(destination), Some(_), Some(_)) if source != destination => {
            Ok((source, destination))
        }
        _ => Err(InvalidMapsDomainEvent::MalformedStorageEvent),
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidMapsDomainEvent {
    #[error("storage event belongs to another bounded context")]
    UnexpectedNamespace,
    #[error("storage event shape is inconsistent with its mutation kind")]
    MalformedStorageEvent,
    #[error("storage event contains a path that is not a map file")]
    InvalidMapPath(#[from] InvalidMapFilePath),
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::shared::{
        file_storage::{
            event::FileChanged,
            guard::BackupReceipt,
            mutation::{FileMutationKind, StorageNamespace},
        },
        user_role::UserRole,
    };

    fn path(value: &str) -> RelativeStoragePath {
        RelativeStoragePath::new(value).unwrap()
    }

    fn revision(timestamp: i64) -> FileRevision {
        FileRevision::from_metadata(10, Utc.timestamp_opt(timestamp, 0).unwrap())
    }

    #[allow(clippy::too_many_arguments)]
    fn storage_event(
        namespace: &str,
        kind: FileMutationKind,
        source: Option<RelativeStoragePath>,
        destination: Option<RelativeStoragePath>,
        previous_revision: Option<FileRevision>,
        current_revision: Option<FileRevision>,
        backup_receipt: Option<BackupReceipt>,
    ) -> FileChanged {
        FileChanged::new(
            backup_receipt
                .as_ref()
                .map(BackupReceipt::mutation_id)
                .unwrap_or_default(),
            StorageNamespace::new(namespace).unwrap(),
            MutationActor::new("42", Some("session-1".into())).unwrap(),
            Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
            kind,
            source,
            destination,
            previous_revision,
            current_revision,
            backup_receipt,
        )
    }

    fn access() -> MapAccess {
        MapAccess::authorize(UserRole::Mapper, &[]).unwrap()
    }

    #[test]
    fn maps_all_storage_mutations_with_nested_paths() {
        let previous = revision(1_700_000_000);
        let current = revision(1_700_000_100);
        let cases = [
            (
                storage_event(
                    "maps",
                    FileMutationKind::Create,
                    None,
                    Some(path("city/new.map")),
                    None,
                    Some(current.clone()),
                    None,
                ),
                MapFileChange::Created {
                    path: MapFilePath::new(path("city/new.map")).unwrap(),
                },
            ),
            (
                storage_event(
                    "maps",
                    FileMutationKind::Overwrite,
                    Some(path("city/race.map")),
                    Some(path("city/race.map")),
                    Some(previous.clone()),
                    Some(current.clone()),
                    None,
                ),
                MapFileChange::Overwritten {
                    path: MapFilePath::new(path("city/race.map")).unwrap(),
                },
            ),
            (
                storage_event(
                    "maps",
                    FileMutationKind::Delete,
                    Some(path("old/race.map.off")),
                    None,
                    Some(previous.clone()),
                    None,
                    None,
                ),
                MapFileChange::Deleted {
                    path: MapFilePath::new(path("old/race.map.off")).unwrap(),
                },
            ),
            (
                storage_event(
                    "maps",
                    FileMutationKind::Rename,
                    Some(path("city/race.map")),
                    Some(path("archive/race.map.off")),
                    Some(previous),
                    Some(current),
                    None,
                ),
                MapFileChange::Renamed {
                    source: MapFilePath::new(path("city/race.map")).unwrap(),
                    destination: MapFilePath::new(path("archive/race.map.off")).unwrap(),
                },
            ),
        ];

        for (storage, expected) in cases {
            let event = MapFileChanged::from_storage(&storage, access()).unwrap();
            assert_eq!(event.change(), &expected);
            assert_eq!(event.event_id().mutation_id(), storage.mutation_id());
            assert_eq!(event.access_level(), MapAccessLevel::Mapper);
        }
    }

    #[test]
    fn preserves_backup_receipt_and_stable_event_identity() {
        let previous = revision(1_700_000_000);
        let mutation_id = MutationId::new();
        let receipt = BackupReceipt::new(
            mutation_id,
            "maps-backup-1",
            previous.clone(),
            Utc.timestamp_opt(1_700_000_050, 0).unwrap(),
        )
        .unwrap();
        let storage = storage_event(
            "maps",
            FileMutationKind::Delete,
            Some(path("city/race.map")),
            None,
            Some(previous),
            None,
            Some(receipt.clone()),
        );
        let changed = MapFileChanged::from_storage(&storage, access()).unwrap();
        let event = MapsDomainEvent::from(changed.clone());

        assert_eq!(changed.backup_receipt(), Some(&receipt));
        assert_eq!(event.event_id().mutation_id(), mutation_id);
        assert_eq!(event.event_type(), MAP_FILE_CHANGED_EVENT_TYPE);
        assert!(
            event
                .event_id()
                .to_string()
                .starts_with("maps.file-changed.v1:")
        );
    }

    #[test]
    fn rejects_wrong_namespace_malformed_shape_and_non_map_path() {
        let current = revision(1_700_000_100);
        let wrong_namespace = storage_event(
            "configuration",
            FileMutationKind::Create,
            None,
            Some(path("race.map")),
            None,
            Some(current.clone()),
            None,
        );
        assert_eq!(
            MapFileChanged::from_storage(&wrong_namespace, access()),
            Err(InvalidMapsDomainEvent::UnexpectedNamespace)
        );

        let malformed = storage_event(
            "maps",
            FileMutationKind::Create,
            Some(path("unexpected.map")),
            Some(path("race.map")),
            None,
            Some(current.clone()),
            None,
        );
        assert_eq!(
            MapFileChanged::from_storage(&malformed, access()),
            Err(InvalidMapsDomainEvent::MalformedStorageEvent)
        );

        let invalid_path = storage_event(
            "maps",
            FileMutationKind::Create,
            None,
            Some(path("race.xml")),
            None,
            Some(current),
            None,
        );
        assert!(matches!(
            MapFileChanged::from_storage(&invalid_path, access()),
            Err(InvalidMapsDomainEvent::InvalidMapPath(
                InvalidMapFilePath::UnsupportedExtension
            ))
        ));
    }
}
