use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::configuration::{
    application::file_service::{ConfigurationTreeEntry, ConfigurationTreeEntryKind},
    domain::ConfigurationFileChanged,
};

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct FilePathQuery {
    /// Slash-separated path relative to the caller's configuration capability.
    pub path: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WriteFileRequest {
    /// Slash-separated path relative to the caller's configuration capability.
    pub path: String,
    pub content: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RenameFileRequest {
    pub source: String,
    pub destination: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationTreeResponse {
    pub entries: Vec<ConfigurationTreeEntryResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationTreeEntryResponse {
    pub path: String,
    pub name: String,
    pub kind: ConfigurationTreeEntryKindResponse,
    pub size: Option<u64>,
    /// RFC 3339 UTC timestamp. Directories may not expose one.
    pub modified_at: Option<String>,
    #[schema(no_recursion)]
    pub children: Vec<ConfigurationTreeEntryResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationTreeEntryKindResponse {
    Directory,
    Text,
    Binary,
}

impl From<ConfigurationTreeEntry> for ConfigurationTreeEntryResponse {
    fn from(entry: ConfigurationTreeEntry) -> Self {
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

impl From<ConfigurationTreeEntryKind> for ConfigurationTreeEntryKindResponse {
    fn from(kind: ConfigurationTreeEntryKind) -> Self {
        match kind {
            ConfigurationTreeEntryKind::Directory => Self::Directory,
            ConfigurationTreeEntryKind::Text => Self::Text,
            ConfigurationTreeEntryKind::Binary => Self::Binary,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileMutationResponse {
    pub event_id: String,
    pub event_type: String,
    pub mutation_id: String,
    /// RFC 3339 UTC timestamp.
    pub occurred_at: String,
}

impl From<ConfigurationFileChanged> for FileMutationResponse {
    fn from(event: ConfigurationFileChanged) -> Self {
        let event_id = event.event_id();
        Self {
            event_id: event_id.to_string(),
            event_type: crate::configuration::domain::CONFIGURATION_FILE_CHANGED_EVENT_TYPE.into(),
            mutation_id: event_id.mutation_id().to_string(),
            occurred_at: event.occurred_at().to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub code: &'static str,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::shared::file_storage::path::RelativeStoragePath;

    #[test]
    fn maps_recursive_tree_to_a_camel_case_response() {
        let response = ConfigurationTreeResponse {
            entries: vec![ConfigurationTreeEntry {
                path: RelativeStoragePath::new("configs").unwrap(),
                name: "configs".into(),
                kind: ConfigurationTreeEntryKind::Directory,
                size: None,
                modified_at: None,
                children: vec![ConfigurationTreeEntry {
                    path: RelativeStoragePath::new("configs/server.cfg").unwrap(),
                    name: "server.cfg".into(),
                    kind: ConfigurationTreeEntryKind::Text,
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
        assert_eq!(value["entries"][0]["children"][0]["kind"], "text");
        assert_eq!(value["entries"][0]["children"][0]["size"], 42);
        assert!(value["entries"][0]["children"][0]["modifiedAt"].is_string());
    }
}
