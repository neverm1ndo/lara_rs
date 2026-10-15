use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::maps::{
    application::file_service::{MapsTreeEntry, MapsTreeEntryKind},
    domain::{MAP_FILE_CHANGED_EVENT_TYPE, MapFileChanged},
};

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct MapFilePathQuery {
    /// Slash-separated `.map` or `.map.off` path relative to the maps root.
    pub path: String,
}

/// OpenAPI representation of a multipart batch. Every part must be named
/// `files`; each filename is its destination path relative to the maps root.
#[derive(Debug, ToSchema)]
pub struct MapFilesUpload {
    #[schema(format = Binary)]
    pub files: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RenameMapFileRequest {
    pub source: String,
    pub destination: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MapsTreeResponse {
    pub entries: Vec<MapsTreeEntryResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MapsTreeEntryResponse {
    pub path: String,
    pub name: String,
    pub kind: MapsTreeEntryKindResponse,
    pub size: Option<u64>,
    /// RFC 3339 UTC timestamp. Directories do not expose one.
    pub modified_at: Option<String>,
    #[schema(no_recursion)]
    pub children: Vec<MapsTreeEntryResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MapsTreeEntryKindResponse {
    Directory,
    ActiveMap,
    DisabledMap,
}

impl From<MapsTreeEntry> for MapsTreeEntryResponse {
    fn from(entry: MapsTreeEntry) -> Self {
        Self {
            path: entry.path.to_string(),
            name: entry.name,
            kind: entry.kind.into(),
            size: entry.size,
            modified_at: entry.modified_at.map(|value| value.to_rfc3339()),
            children: entry.children.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<MapsTreeEntryKind> for MapsTreeEntryKindResponse {
    fn from(kind: MapsTreeEntryKind) -> Self {
        match kind {
            MapsTreeEntryKind::Directory => Self::Directory,
            MapsTreeEntryKind::ActiveMap => Self::ActiveMap,
            MapsTreeEntryKind::DisabledMap => Self::DisabledMap,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MapFileMutationResponse {
    pub event_id: String,
    pub event_type: String,
    pub mutation_id: String,
    /// RFC 3339 UTC timestamp.
    pub occurred_at: String,
}

impl From<MapFileChanged> for MapFileMutationResponse {
    fn from(event: MapFileChanged) -> Self {
        let event_id = event.event_id();
        Self {
            event_id: event_id.to_string(),
            event_type: MAP_FILE_CHANGED_EVENT_TYPE.into(),
            mutation_id: event_id.mutation_id().to_string(),
            occurred_at: event.occurred_at().to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MapFileMutationsResponse {
    pub events: Vec<MapFileMutationResponse>,
}

impl From<Vec<MapFileChanged>> for MapFileMutationsResponse {
    fn from(events: Vec<MapFileChanged>) -> Self {
        Self {
            events: events.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MapsErrorResponse {
    pub code: &'static str,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::shared::file_storage::path::RelativeStoragePath;

    #[test]
    fn maps_recursive_tree_to_transport_dto() {
        let response = MapsTreeResponse {
            entries: vec![MapsTreeEntry {
                path: RelativeStoragePath::new("city").unwrap(),
                name: "city".into(),
                kind: MapsTreeEntryKind::Directory,
                size: None,
                modified_at: None,
                children: vec![MapsTreeEntry {
                    path: RelativeStoragePath::new("city/race.map.off").unwrap(),
                    name: "race.map.off".into(),
                    kind: MapsTreeEntryKind::DisabledMap,
                    size: Some(42),
                    modified_at: Some(chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap()),
                    children: vec![],
                }],
            }]
            .into_iter()
            .map(Into::into)
            .collect(),
        };

        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["entries"][0]["kind"], "directory");
        assert_eq!(value["entries"][0]["children"][0]["kind"], "disabled_map");
        assert_eq!(value["entries"][0]["children"][0]["size"], 42);
        assert!(value["entries"][0]["children"][0]["modifiedAt"].is_string());
    }
}
