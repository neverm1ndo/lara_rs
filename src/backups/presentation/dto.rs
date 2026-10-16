use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::backups::{
    application::ports::{BackupListCursor, BackupListQuery},
    domain::{
        Backup, BackupAction, BackupDiff, BackupDiffSkipReason, BackupId, BackupState,
        SnapshotCompression,
    },
};

const DEFAULT_PAGE_SIZE: usize = 50;
const MAX_PAGE_SIZE: usize = 100;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct BackupListParameters {
    /// RFC 3339 timestamp from `nextCursor.createdAt`.
    pub cursor_created_at: Option<String>,
    /// UUID from `nextCursor.backupId`.
    pub cursor_backup_id: Option<String>,
    /// Number of records, from 1 to 100. Defaults to 50.
    pub limit: Option<usize>,
}

impl BackupListParameters {
    pub fn into_query(self) -> Result<BackupListQuery, InvalidBackupListParameters> {
        let limit = self.limit.unwrap_or(DEFAULT_PAGE_SIZE);
        if limit == 0 || limit > MAX_PAGE_SIZE {
            return Err(InvalidBackupListParameters);
        }
        let cursor = match (self.cursor_created_at, self.cursor_backup_id) {
            (None, None) => None,
            (Some(created_at), Some(backup_id)) => Some(BackupListCursor {
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at)
                    .map_err(|_| InvalidBackupListParameters)?
                    .with_timezone(&chrono::Utc),
                backup_id: backup_id
                    .parse::<BackupId>()
                    .map_err(|_| InvalidBackupListParameters)?,
            }),
            _ => return Err(InvalidBackupListParameters),
        };
        BackupListQuery::new(cursor, limit).map_err(|_| InvalidBackupListParameters)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InvalidBackupListParameters;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackupListResponse {
    pub backups: Vec<BackupResponse>,
    pub next_cursor: Option<BackupCursorResponse>,
}

impl BackupListResponse {
    pub fn from_backups(backups: Vec<Backup>) -> Self {
        let next_cursor = backups.last().map(|backup| BackupCursorResponse {
            created_at: backup.created_at().to_rfc3339(),
            backup_id: backup.id().to_string(),
        });
        Self {
            backups: backups.iter().map(BackupResponse::from).collect(),
            next_cursor,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackupCursorResponse {
    /// RFC 3339 UTC timestamp.
    pub created_at: String,
    pub backup_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackupResponse {
    pub id: String,
    pub mutation_id: String,
    pub namespace: String,
    pub path: String,
    pub action: BackupActionResponse,
    pub initiated_by: i64,
    /// RFC 3339 UTC timestamp.
    pub created_at: String,
    /// RFC 3339 UTC timestamp.
    pub expires_at: String,
    pub state: BackupStateResponse,
    pub snapshot: Option<BackupSnapshotResponse>,
    pub diff: Option<BackupDiffResponse>,
}

impl From<&Backup> for BackupResponse {
    fn from(backup: &Backup) -> Self {
        Self {
            id: backup.id().to_string(),
            mutation_id: backup.mutation_id().to_string(),
            namespace: backup.source().namespace().to_string(),
            path: backup.source().path().to_string(),
            action: backup.action().into(),
            initiated_by: backup.initiated_by().get(),
            created_at: backup.created_at().to_rfc3339(),
            expires_at: backup.expires_at().to_rfc3339(),
            state: backup.state().into(),
            snapshot: backup.snapshot().map(|snapshot| BackupSnapshotResponse {
                binary: snapshot.content_kind().is_binary(),
                original_bytes: snapshot.original_bytes(),
                stored_bytes: snapshot.stored_bytes(),
                compression: snapshot.compression().into(),
                content_hash: snapshot.content_hash().to_string(),
            }),
            diff: backup.diff().map(Into::into),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BackupActionResponse {
    Overwrite,
    Delete,
}

impl From<BackupAction> for BackupActionResponse {
    fn from(value: BackupAction) -> Self {
        match value {
            BackupAction::Overwrite => Self::Overwrite,
            BackupAction::Delete => Self::Delete,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BackupStateResponse {
    Preparing,
    Available,
    Restoring,
    Deleting,
    PreparationFailed,
}

impl From<BackupState> for BackupStateResponse {
    fn from(value: BackupState) -> Self {
        match value {
            BackupState::Preparing { .. } => Self::Preparing,
            BackupState::Available => Self::Available,
            BackupState::Restoring { .. } => Self::Restoring,
            BackupState::Deleting { .. } => Self::Deleting,
            BackupState::PreparationFailed => Self::PreparationFailed,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackupSnapshotResponse {
    pub binary: bool,
    pub original_bytes: u64,
    pub stored_bytes: u64,
    pub compression: SnapshotCompressionResponse,
    pub content_hash: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotCompressionResponse {
    None,
    Gzip,
}

impl From<SnapshotCompression> for SnapshotCompressionResponse {
    fn from(value: SnapshotCompression) -> Self {
        match value {
            SnapshotCompression::None => Self::None,
            SnapshotCompression::Gzip => Self::Gzip,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BackupDiffResponse {
    DiffMatchPatch {
        patch: String,
    },
    Skipped {
        reason: BackupDiffSkipReasonResponse,
    },
}

impl From<&BackupDiff> for BackupDiffResponse {
    fn from(value: &BackupDiff) -> Self {
        match value {
            BackupDiff::DiffMatchPatch(patch) => Self::DiffMatchPatch {
                patch: patch.clone(),
            },
            BackupDiff::Skipped(reason) => Self::Skipped {
                reason: (*reason).into(),
            },
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BackupDiffSkipReasonResponse {
    BinaryContent,
    Disabled,
    InputTooLarge,
    UnsupportedEncoding,
    GenerationTimedOut,
    GenerationFailed,
}

impl From<BackupDiffSkipReason> for BackupDiffSkipReasonResponse {
    fn from(value: BackupDiffSkipReason) -> Self {
        match value {
            BackupDiffSkipReason::BinaryContent => Self::BinaryContent,
            BackupDiffSkipReason::Disabled => Self::Disabled,
            BackupDiffSkipReason::InputTooLarge => Self::InputTooLarge,
            BackupDiffSkipReason::UnsupportedEncoding => Self::UnsupportedEncoding,
            BackupDiffSkipReason::GenerationTimedOut => Self::GenerationTimedOut,
            BackupDiffSkipReason::GenerationFailed => Self::GenerationFailed,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BackupsErrorResponse {
    pub code: &'static str,
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone, Utc};

    use super::*;
    use crate::{
        backups::domain::{
            BackupAction, BackupInitiatorId, BackupSnapshot, BackupSource, SnapshotCompression,
        },
        shared::file_storage::{
            content::FileContentKind,
            mutation::{
                ContentHashAlgorithm, FileContentHash, FileRevision, MutationId, StorageNamespace,
            },
            path::RelativeStoragePath,
        },
    };

    fn now() -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000, 0).unwrap()
    }

    fn backup(diff: BackupDiff, kind: FileContentKind) -> Backup {
        let revision = FileRevision::from_metadata(3, now());
        let mut backup = Backup::prepare(
            BackupId::new(),
            MutationId::new(),
            BackupSource::new(
                StorageNamespace::new("configuration").unwrap(),
                RelativeStoragePath::new("server.cfg").unwrap(),
            )
            .unwrap(),
            BackupAction::Overwrite,
            BackupInitiatorId::new(42).unwrap(),
            revision.clone(),
            now(),
            now() + Duration::hours(1),
            now() + Duration::minutes(1),
        )
        .unwrap();
        backup
            .mark_available(
                BackupSnapshot::new(
                    revision,
                    FileContentHash::new(ContentHashAlgorithm::Sha256, "00".repeat(32)).unwrap(),
                    kind,
                    3,
                    3,
                    SnapshotCompression::None,
                )
                .unwrap(),
                diff,
            )
            .unwrap();
        backup
    }

    #[test]
    fn cursor_requires_both_valid_parts_and_bounded_limit() {
        let id = BackupId::new();
        let query = BackupListParameters {
            cursor_created_at: Some(now().to_rfc3339()),
            cursor_backup_id: Some(id.to_string()),
            limit: Some(100),
        }
        .into_query()
        .unwrap();
        assert_eq!(query.cursor.unwrap().backup_id, id);
        assert_eq!(query.limit, 100);

        for parameters in [
            BackupListParameters {
                cursor_created_at: Some(now().to_rfc3339()),
                cursor_backup_id: None,
                limit: None,
            },
            BackupListParameters {
                cursor_created_at: Some("invalid".into()),
                cursor_backup_id: Some(id.to_string()),
                limit: None,
            },
            BackupListParameters {
                cursor_created_at: None,
                cursor_backup_id: None,
                limit: Some(101),
            },
        ] {
            assert!(parameters.into_query().is_err());
        }
    }

    #[test]
    fn serializes_patch_and_binary_skip_without_snapshot_bytes() {
        let text = BackupListResponse::from_backups(vec![backup(
            BackupDiff::DiffMatchPatch("@@ patch @@".into()),
            FileContentKind::Text,
        )]);
        let text = serde_json::to_value(text).unwrap();
        assert_eq!(text["backups"][0]["diff"]["kind"], "diff_match_patch");
        assert_eq!(text["backups"][0]["diff"]["patch"], "@@ patch @@");
        assert_eq!(text["backups"][0]["snapshot"]["binary"], false);

        let binary = BackupListResponse::from_backups(vec![backup(
            BackupDiff::Skipped(BackupDiffSkipReason::BinaryContent),
            FileContentKind::Binary,
        )]);
        let binary = serde_json::to_value(binary).unwrap();
        assert_eq!(binary["backups"][0]["diff"]["kind"], "skipped");
        assert_eq!(binary["backups"][0]["diff"]["reason"], "binary_content");
        assert_eq!(binary["backups"][0]["snapshot"]["binary"], true);
        assert!(binary["backups"][0].get("content").is_none());
    }
}
