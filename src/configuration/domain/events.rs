use chrono::{DateTime, Utc};
use thiserror::Error;

use super::{ConfigurationAccess, ConfigurationAccessLevel};
use crate::shared::file_storage::{
    event::FileChanged,
    guard::BackupReceipt,
    mutation::{FileMutationKind, FileRevision, MutationActor, MutationId},
    path::RelativeStoragePath,
};

const CONFIGURATION_STORAGE_NAMESPACE: &str = "configuration";
pub const CONFIGURATION_FILE_CHANGED_EVENT_TYPE: &str = "configuration.file-changed.v1";

/// Stable event identity. One configuration event is emitted for each
/// successful storage mutation, so the mutation ID is also the idempotency key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConfigurationEventId(MutationId);

impl ConfigurationEventId {
    pub fn mutation_id(self) -> MutationId {
        self.0
    }
}

impl std::fmt::Display for ConfigurationEventId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{CONFIGURATION_FILE_CHANGED_EVENT_TYPE}:{}",
            self.0
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigurationFileChange {
    Created {
        path: RelativeStoragePath,
    },
    Overwritten {
        path: RelativeStoragePath,
    },
    Deleted {
        path: RelativeStoragePath,
    },
    Renamed {
        source: RelativeStoragePath,
        destination: RelativeStoragePath,
    },
}

impl ConfigurationFileChange {
    pub fn source(&self) -> Option<&RelativeStoragePath> {
        match self {
            Self::Created { .. } => None,
            Self::Overwritten { path } | Self::Deleted { path } => Some(path),
            Self::Renamed { source, .. } => Some(source),
        }
    }

    pub fn destination(&self) -> Option<&RelativeStoragePath> {
        match self {
            Self::Deleted { .. } => None,
            Self::Created { path } | Self::Overwritten { path } => Some(path),
            Self::Renamed { destination, .. } => Some(destination),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationFileChanged {
    event_id: ConfigurationEventId,
    actor: MutationActor,
    access_level: ConfigurationAccessLevel,
    occurred_at: DateTime<Utc>,
    change: ConfigurationFileChange,
    previous_revision: Option<FileRevision>,
    current_revision: Option<FileRevision>,
    backup_receipt: Option<BackupReceipt>,
}

impl ConfigurationFileChanged {
    /// Converts the storage result into a domain event. Storage paths are
    /// relative to the request capability and are mapped back into the global
    /// game-server namespace before entering the event.
    pub fn from_storage(
        storage_event: &FileChanged,
        access: &ConfigurationAccess,
    ) -> Result<Self, InvalidConfigurationDomainEvent> {
        if storage_event.namespace().as_str() != CONFIGURATION_STORAGE_NAMESPACE {
            return Err(InvalidConfigurationDomainEvent::UnexpectedNamespace);
        }

        let server_path = |path: &RelativeStoragePath| access.server_path(path);
        let change = match storage_event.kind() {
            FileMutationKind::Create => {
                let path = valid_create(storage_event)?;
                ConfigurationFileChange::Created {
                    path: server_path(path),
                }
            }
            FileMutationKind::Overwrite => {
                let path = valid_overwrite(storage_event)?;
                ConfigurationFileChange::Overwritten {
                    path: server_path(path),
                }
            }
            FileMutationKind::Delete => {
                let path = valid_delete(storage_event)?;
                ConfigurationFileChange::Deleted {
                    path: server_path(path),
                }
            }
            FileMutationKind::Rename => {
                let (source, destination) = valid_rename(storage_event)?;
                ConfigurationFileChange::Renamed {
                    source: server_path(source),
                    destination: server_path(destination),
                }
            }
        };

        Ok(Self {
            event_id: ConfigurationEventId(storage_event.mutation_id()),
            actor: storage_event.actor().clone(),
            access_level: access.level(),
            occurred_at: storage_event.occurred_at(),
            change,
            previous_revision: storage_event.previous_revision().cloned(),
            current_revision: storage_event.current_revision().cloned(),
            backup_receipt: storage_event.backup_receipt().cloned(),
        })
    }

    pub fn event_id(&self) -> ConfigurationEventId {
        self.event_id
    }

    pub fn actor(&self) -> &MutationActor {
        &self.actor
    }

    pub fn access_level(&self) -> ConfigurationAccessLevel {
        self.access_level
    }

    pub fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }

    pub fn change(&self) -> &ConfigurationFileChange {
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
pub enum ConfigurationDomainEvent {
    FileChanged(ConfigurationFileChanged),
}

impl ConfigurationDomainEvent {
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::FileChanged(_) => CONFIGURATION_FILE_CHANGED_EVENT_TYPE,
        }
    }

    pub fn event_id(&self) -> ConfigurationEventId {
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

impl From<ConfigurationFileChanged> for ConfigurationDomainEvent {
    fn from(event: ConfigurationFileChanged) -> Self {
        Self::FileChanged(event)
    }
}

fn valid_create(
    event: &FileChanged,
) -> Result<&RelativeStoragePath, InvalidConfigurationDomainEvent> {
    match (
        event.source(),
        event.destination(),
        event.previous_revision(),
        event.current_revision(),
    ) {
        (None, Some(destination), None, Some(_)) => Ok(destination),
        _ => Err(InvalidConfigurationDomainEvent::MalformedStorageEvent),
    }
}

fn valid_overwrite(
    event: &FileChanged,
) -> Result<&RelativeStoragePath, InvalidConfigurationDomainEvent> {
    match (
        event.source(),
        event.destination(),
        event.previous_revision(),
        event.current_revision(),
    ) {
        (Some(source), Some(destination), Some(_), Some(_)) if source == destination => Ok(source),
        _ => Err(InvalidConfigurationDomainEvent::MalformedStorageEvent),
    }
}

fn valid_delete(
    event: &FileChanged,
) -> Result<&RelativeStoragePath, InvalidConfigurationDomainEvent> {
    match (
        event.source(),
        event.destination(),
        event.previous_revision(),
        event.current_revision(),
    ) {
        (Some(source), None, Some(_), None) => Ok(source),
        _ => Err(InvalidConfigurationDomainEvent::MalformedStorageEvent),
    }
}

fn valid_rename(
    event: &FileChanged,
) -> Result<(&RelativeStoragePath, &RelativeStoragePath), InvalidConfigurationDomainEvent> {
    match (
        event.source(),
        event.destination(),
        event.previous_revision(),
        event.current_revision(),
    ) {
        (Some(source), Some(destination), Some(_), Some(_)) if source != destination => {
            Ok((source, destination))
        }
        _ => Err(InvalidConfigurationDomainEvent::MalformedStorageEvent),
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidConfigurationDomainEvent {
    #[error("storage event belongs to another bounded context")]
    UnexpectedNamespace,
    #[error("storage event shape is inconsistent with its mutation kind")]
    MalformedStorageEvent,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::shared::{
        file_storage::{
            event::FileChanged,
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

    fn access(role: UserRole) -> ConfigurationAccess {
        ConfigurationAccess::authorize(role, &[], &path("scriptfiles/config")).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn storage_event(
        namespace: &str,
        kind: FileMutationKind,
        source: Option<RelativeStoragePath>,
        destination: Option<RelativeStoragePath>,
        previous_revision: Option<FileRevision>,
        current_revision: Option<FileRevision>,
    ) -> FileChanged {
        FileChanged::new(
            MutationId::new(),
            StorageNamespace::new(namespace).unwrap(),
            MutationActor::new("42", Some("session-1".into())).unwrap(),
            Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
            kind,
            source,
            destination,
            previous_revision,
            current_revision,
            None,
        )
    }

    #[test]
    fn maps_all_storage_mutations_to_typed_domain_changes() {
        let previous = revision(1_700_000_000);
        let current = revision(1_700_000_100);
        let cases = [
            (
                storage_event(
                    "configuration",
                    FileMutationKind::Create,
                    None,
                    Some(path("new.cfg")),
                    None,
                    Some(current.clone()),
                ),
                ConfigurationFileChange::Created {
                    path: path("new.cfg"),
                },
            ),
            (
                storage_event(
                    "configuration",
                    FileMutationKind::Overwrite,
                    Some(path("server.cfg")),
                    Some(path("server.cfg")),
                    Some(previous.clone()),
                    Some(current.clone()),
                ),
                ConfigurationFileChange::Overwritten {
                    path: path("server.cfg"),
                },
            ),
            (
                storage_event(
                    "configuration",
                    FileMutationKind::Delete,
                    Some(path("old.cfg")),
                    None,
                    Some(previous.clone()),
                    None,
                ),
                ConfigurationFileChange::Deleted {
                    path: path("old.cfg"),
                },
            ),
            (
                storage_event(
                    "configuration",
                    FileMutationKind::Rename,
                    Some(path("old.cfg")),
                    Some(path("new.cfg")),
                    Some(previous),
                    Some(current),
                ),
                ConfigurationFileChange::Renamed {
                    source: path("old.cfg"),
                    destination: path("new.cfg"),
                },
            ),
        ];

        for (storage, expected) in cases {
            let event =
                ConfigurationFileChanged::from_storage(&storage, &access(UserRole::Developer))
                    .unwrap();

            assert_eq!(event.change(), &expected);
            assert_eq!(event.event_id().mutation_id(), storage.mutation_id());
            assert_eq!(event.occurred_at(), storage.occurred_at());
        }
    }

    #[test]
    fn expands_configurator_paths_to_the_server_root_namespace() {
        let storage = storage_event(
            "configuration",
            FileMutationKind::Delete,
            Some(path("private/server.cfg")),
            None,
            Some(revision(1_700_000_000)),
            None,
        );

        let event =
            ConfigurationFileChanged::from_storage(&storage, &access(UserRole::Configurator))
                .unwrap();

        assert_eq!(
            event.change(),
            &ConfigurationFileChange::Deleted {
                path: path("scriptfiles/config/private/server.cfg")
            }
        );
        assert_eq!(event.access_level(), ConfigurationAccessLevel::Configurator);
    }

    #[test]
    fn rejects_another_namespace_and_malformed_event_shapes() {
        let other_context = storage_event(
            "maps",
            FileMutationKind::Delete,
            Some(path("map.pwn")),
            None,
            Some(revision(1_700_000_000)),
            None,
        );
        assert_eq!(
            ConfigurationFileChanged::from_storage(&other_context, &access(UserRole::Developer)),
            Err(InvalidConfigurationDomainEvent::UnexpectedNamespace)
        );

        let malformed = storage_event(
            "configuration",
            FileMutationKind::Create,
            Some(path("unexpected.cfg")),
            Some(path("new.cfg")),
            None,
            Some(revision(1_700_000_100)),
        );
        assert_eq!(
            ConfigurationFileChanged::from_storage(&malformed, &access(UserRole::Developer)),
            Err(InvalidConfigurationDomainEvent::MalformedStorageEvent)
        );
    }

    #[test]
    fn domain_event_exposes_a_stable_id_and_timestamp() {
        let storage = storage_event(
            "configuration",
            FileMutationKind::Create,
            None,
            Some(path("new.cfg")),
            None,
            Some(revision(1_700_000_100)),
        );
        let changed =
            ConfigurationFileChanged::from_storage(&storage, &access(UserRole::Developer)).unwrap();
        let expected_id = changed.event_id();
        let expected_time = changed.occurred_at();
        let event = ConfigurationDomainEvent::from(changed);

        assert_eq!(event.event_id(), expected_id);
        assert_eq!(event.occurred_at(), expected_time);
        assert_eq!(event.event_type(), CONFIGURATION_FILE_CHANGED_EVENT_TYPE);
        assert!(
            event
                .event_id()
                .to_string()
                .starts_with(&format!("{CONFIGURATION_FILE_CHANGED_EVENT_TYPE}:"))
        );
    }
}
