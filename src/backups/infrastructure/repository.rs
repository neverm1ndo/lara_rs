use chrono::{DateTime, Utc};
use mongodb::{
    Collection, Database, IndexModel,
    bson::{DateTime as BsonDateTime, doc},
    error::{Error as MongoError, ErrorKind, WriteFailure},
    options::IndexOptions,
};
use serde::{Deserialize, Serialize};

use crate::{
    backups::{
        application::ports::{
            BackupListQuery, BackupRepository, BackupRepositoryError, BackupRepositoryFuture,
        },
        domain::{
            Backup, BackupAction, BackupDiff, BackupDiffSkipReason, BackupId, BackupInitiatorId,
            BackupSnapshot, BackupSource, BackupState, BackupVersion, SnapshotCompression,
        },
    },
    shared::file_storage::{
        content::FileContentKind,
        mutation::{
            ContentHashAlgorithm, FileContentHash, FileRevision, MutationId, StorageNamespace,
        },
        path::RelativeStoragePath,
    },
};

const BACKUP_COLLECTION: &str = "backups";
const DUPLICATE_KEY_CODE: i32 = 11_000;
// MongoDB documents are limited to 16 MiB. Keep headroom for metadata and
// future schema evolution instead of allowing a generated patch to consume
// the complete document budget.
const MAX_INLINE_DIFF_BYTES: usize = 12 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct MongoBackupRepository {
    backups: Collection<BackupDocument>,
}

impl MongoBackupRepository {
    pub fn new(database: Database) -> Self {
        Self {
            backups: database.collection(BACKUP_COLLECTION),
        }
    }

    /// Creates indexes used by idempotency, cursor pagination and workers.
    /// There is deliberately no TTL index: snapshot files must be removed
    /// before their metadata, while MongoDB TTL deletion is asynchronous and
    /// cannot coordinate that filesystem operation.
    pub async fn ensure_indexes(&self) -> Result<(), BackupRepositoryError> {
        let mutation = IndexModel::builder()
            .keys(doc! { "mutation_id": 1 })
            .options(
                IndexOptions::builder()
                    .name(Some("backups_mutation_id_unique".into()))
                    .unique(Some(true))
                    .build(),
            )
            .build();
        let listing = IndexModel::builder()
            .keys(doc! { "state.kind": 1, "created_at": -1, "_id": -1 })
            .options(
                IndexOptions::builder()
                    .name(Some("backups_created_at_id".into()))
                    .build(),
            )
            .build();
        let expiration = IndexModel::builder()
            .keys(doc! { "state.kind": 1, "expires_at": 1 })
            .options(
                IndexOptions::builder()
                    .name(Some("backups_expiration_state".into()))
                    .build(),
            )
            .build();
        let preparation_lease = IndexModel::builder()
            .keys(doc! { "state.kind": 1, "state.lease_expires_at": 1 })
            .options(
                IndexOptions::builder()
                    .name(Some("backups_state_lease".into()))
                    .build(),
            )
            .build();

        self.backups
            .create_indexes([mutation, listing, expiration, preparation_lease])
            .await
            .map_err(database_error)?;
        Ok(())
    }

    async fn collect(
        &self,
        filter: mongodb::bson::Document,
        sort: mongodb::bson::Document,
        limit: usize,
    ) -> Result<Vec<Backup>, BackupRepositoryError> {
        if limit == 0 {
            return Err(invalid_data("query limit must be greater than zero"));
        }
        let limit = i64::try_from(limit).map_err(|_| invalid_data("query limit exceeds i64"))?;
        let mut cursor = self
            .backups
            .find(filter)
            .sort(sort)
            .limit(limit)
            .await
            .map_err(database_error)?;
        let mut backups = Vec::new();
        while cursor.advance().await.map_err(database_error)? {
            let document = cursor.deserialize_current().map_err(database_error)?;
            backups.push(Backup::try_from(document)?);
        }
        Ok(backups)
    }
}

impl BackupRepository for MongoBackupRepository {
    fn insert<'a>(&'a self, backup: &'a Backup) -> BackupRepositoryFuture<'a, ()> {
        Box::pin(async move {
            let document = BackupDocument::try_from(backup)?;
            match self.backups.insert_one(document).await {
                Ok(_) => Ok(()),
                Err(error) if is_duplicate_key(&error) => Err(BackupRepositoryError::AlreadyExists),
                Err(error) => Err(database_error(error)),
            }
        })
    }

    fn find_by_id<'a>(&'a self, backup_id: BackupId) -> BackupRepositoryFuture<'a, Option<Backup>> {
        Box::pin(async move {
            self.backups
                .find_one(doc! { "_id": backup_id.to_string() })
                .await
                .map_err(database_error)?
                .map(Backup::try_from)
                .transpose()
        })
    }

    fn list<'a>(&'a self, query: BackupListQuery) -> BackupRepositoryFuture<'a, Vec<Backup>> {
        Box::pin(async move {
            let visible = doc! { "state.kind": { "$in": ["available", "restoring"] } };
            let filter = query.cursor.map_or(visible.clone(), |cursor| {
                let created_at = to_bson_datetime(cursor.created_at);
                doc! {
                    "$and": [
                        visible,
                        { "$or": [
                            { "created_at": { "$lt": created_at } },
                            {
                                "created_at": created_at,
                                "_id": { "$lt": cursor.backup_id.to_string() }
                            }
                        ] }
                    ]
                }
            });
            self.collect(filter, doc! { "created_at": -1, "_id": -1 }, query.limit)
                .await
        })
    }

    fn find_expired<'a>(
        &'a self,
        expired_at_or_before: DateTime<Utc>,
        limit: usize,
    ) -> BackupRepositoryFuture<'a, Vec<Backup>> {
        Box::pin(async move {
            self.collect(
                doc! {
                    "expires_at": { "$lte": to_bson_datetime(expired_at_or_before) },
                    "state.kind": { "$in": ["available", "preparation_failed"] }
                },
                doc! { "expires_at": 1, "_id": 1 },
                limit,
            )
            .await
        })
    }

    fn find_stale_preparations<'a>(
        &'a self,
        lease_expired_at_or_before: DateTime<Utc>,
        limit: usize,
    ) -> BackupRepositoryFuture<'a, Vec<Backup>> {
        Box::pin(async move {
            self.collect(
                doc! {
                    "state.kind": "preparing",
                    "state.lease_expires_at": {
                        "$lte": to_bson_datetime(lease_expired_at_or_before)
                    }
                },
                doc! { "state.lease_expires_at": 1, "_id": 1 },
                limit,
            )
            .await
        })
    }

    fn find_stale_operations<'a>(
        &'a self,
        lease_expired_at_or_before: DateTime<Utc>,
        limit: usize,
    ) -> BackupRepositoryFuture<'a, Vec<Backup>> {
        Box::pin(async move {
            self.collect(
                doc! {
                    "state.kind": { "$in": ["restoring", "deleting"] },
                    "state.lease_expires_at": {
                        "$lte": to_bson_datetime(lease_expired_at_or_before)
                    }
                },
                doc! { "state.lease_expires_at": 1, "_id": 1 },
                limit,
            )
            .await
        })
    }

    fn save<'a>(
        &'a self,
        backup: &'a Backup,
        expected_version: BackupVersion,
    ) -> BackupRepositoryFuture<'a, ()> {
        Box::pin(async move {
            let next = expected_version
                .get()
                .checked_add(1)
                .ok_or_else(|| invalid_data("expected version overflow"))?;
            if backup.version().get() != next {
                return Err(invalid_data(
                    "aggregate version must be exactly one greater than expected version",
                ));
            }

            let result = self
                .backups
                .replace_one(
                    doc! {
                        "_id": backup.id().to_string(),
                        "version": u64_to_i64(expected_version.get(), "version")?
                    },
                    BackupDocument::try_from(backup)?,
                )
                .await
                .map_err(database_error)?;
            if result.matched_count == 0 {
                return Err(BackupRepositoryError::ConcurrentModification);
            }
            Ok(())
        })
    }

    fn delete<'a>(
        &'a self,
        backup_id: BackupId,
        expected_version: BackupVersion,
    ) -> BackupRepositoryFuture<'a, ()> {
        Box::pin(async move {
            let result = self
                .backups
                .delete_one(doc! {
                    "_id": backup_id.to_string(),
                    "version": u64_to_i64(expected_version.get(), "version")?
                })
                .await
                .map_err(database_error)?;
            if result.deleted_count == 0 {
                return Err(BackupRepositoryError::ConcurrentModification);
            }
            Ok(())
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BackupDocument {
    #[serde(rename = "_id")]
    id: String,
    mutation_id: String,
    namespace: String,
    path: String,
    action: BackupActionDocument,
    initiated_by: i64,
    source_revision: FileRevisionDocument,
    created_at: BsonDateTime,
    expires_at: BsonDateTime,
    state: BackupStateDocument,
    #[serde(default)]
    snapshot: Option<BackupSnapshotDocument>,
    #[serde(default)]
    diff: Option<BackupDiffDocument>,
    version: i64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum BackupActionDocument {
    Overwrite,
    Delete,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct FileRevisionDocument {
    size: i64,
    modified_at: BsonDateTime,
    #[serde(default)]
    content_hash: Option<ContentHashDocument>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ContentHashDocument {
    algorithm: HashAlgorithmDocument,
    digest: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum HashAlgorithmDocument {
    Blake3,
    Sha256,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BackupSnapshotDocument {
    source_revision: FileRevisionDocument,
    content_hash: ContentHashDocument,
    content_kind: ContentKindDocument,
    original_bytes: i64,
    stored_bytes: i64,
    compression: CompressionDocument,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ContentKindDocument {
    Text,
    Binary,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CompressionDocument {
    None,
    Gzip,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum BackupStateDocument {
    Preparing { lease_expires_at: BsonDateTime },
    Available,
    Restoring { lease_expires_at: BsonDateTime },
    Deleting { lease_expires_at: BsonDateTime },
    PreparationFailed,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum BackupDiffDocument {
    DiffMatchPatch { patch: String },
    Skipped { reason: DiffSkipReasonDocument },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum DiffSkipReasonDocument {
    BinaryContent,
    Disabled,
    InputTooLarge,
    UnsupportedEncoding,
    GenerationTimedOut,
}

impl TryFrom<&Backup> for BackupDocument {
    type Error = BackupRepositoryError;

    fn try_from(backup: &Backup) -> Result<Self, Self::Error> {
        if backup
            .diff()
            .is_some_and(|diff| matches!(diff, BackupDiff::DiffMatchPatch(patch) if patch.len() > MAX_INLINE_DIFF_BYTES))
        {
            return Err(invalid_data("Diff Match Patch exceeds the BSON safety limit"));
        }

        Ok(Self {
            id: backup.id().to_string(),
            mutation_id: backup.mutation_id().to_string(),
            namespace: backup.source().namespace().as_str().to_owned(),
            path: backup.source().path().as_normalized_str(),
            action: backup.action().into(),
            initiated_by: backup.initiated_by().get(),
            source_revision: FileRevisionDocument::try_from(backup.source_revision())?,
            created_at: to_bson_datetime(backup.created_at()),
            expires_at: to_bson_datetime(backup.expires_at()),
            state: backup.state().into(),
            snapshot: backup
                .snapshot()
                .map(BackupSnapshotDocument::try_from)
                .transpose()?,
            diff: backup.diff().map(Into::into),
            version: u64_to_i64(backup.version().get(), "version")?,
        })
    }
}

impl TryFrom<BackupDocument> for Backup {
    type Error = BackupRepositoryError;

    fn try_from(document: BackupDocument) -> Result<Self, Self::Error> {
        let version = i64_to_u64(document.version, "version")?;
        Backup::rehydrate(
            parse_backup_id(&document.id)?,
            parse_mutation_id(&document.mutation_id)?,
            BackupSource::new(
                StorageNamespace::new(document.namespace).map_err(invalid_domain)?,
                RelativeStoragePath::new(document.path).map_err(invalid_domain)?,
            )
            .map_err(invalid_domain)?,
            document.action.into(),
            BackupInitiatorId::new(document.initiated_by).map_err(invalid_domain)?,
            FileRevision::try_from(document.source_revision)?,
            from_bson_datetime(document.created_at)?,
            from_bson_datetime(document.expires_at)?,
            BackupState::try_from(document.state)?,
            document
                .snapshot
                .map(BackupSnapshot::try_from)
                .transpose()?,
            document.diff.map(Into::into),
            BackupVersion::from_value(version),
        )
        .map_err(invalid_domain)
    }
}

impl From<BackupAction> for BackupActionDocument {
    fn from(value: BackupAction) -> Self {
        match value {
            BackupAction::Overwrite => Self::Overwrite,
            BackupAction::Delete => Self::Delete,
        }
    }
}

impl From<BackupActionDocument> for BackupAction {
    fn from(value: BackupActionDocument) -> Self {
        match value {
            BackupActionDocument::Overwrite => Self::Overwrite,
            BackupActionDocument::Delete => Self::Delete,
        }
    }
}

impl TryFrom<&FileRevision> for FileRevisionDocument {
    type Error = BackupRepositoryError;

    fn try_from(value: &FileRevision) -> Result<Self, Self::Error> {
        Ok(Self {
            size: u64_to_i64(value.size(), "revision.size")?,
            modified_at: to_bson_datetime(value.modified_at()),
            content_hash: value.content_hash().map(Into::into),
        })
    }
}

impl TryFrom<FileRevisionDocument> for FileRevision {
    type Error = BackupRepositoryError;

    fn try_from(value: FileRevisionDocument) -> Result<Self, Self::Error> {
        Ok(FileRevision::new(
            i64_to_u64(value.size, "revision.size")?,
            from_bson_datetime(value.modified_at)?,
            value
                .content_hash
                .map(FileContentHash::try_from)
                .transpose()?,
        ))
    }
}

impl From<&FileContentHash> for ContentHashDocument {
    fn from(value: &FileContentHash) -> Self {
        Self {
            algorithm: value.algorithm().into(),
            digest: value.hex_digest().to_owned(),
        }
    }
}

impl TryFrom<ContentHashDocument> for FileContentHash {
    type Error = BackupRepositoryError;

    fn try_from(value: ContentHashDocument) -> Result<Self, Self::Error> {
        FileContentHash::new(value.algorithm.into(), value.digest).map_err(invalid_domain)
    }
}

impl From<ContentHashAlgorithm> for HashAlgorithmDocument {
    fn from(value: ContentHashAlgorithm) -> Self {
        match value {
            ContentHashAlgorithm::Blake3 => Self::Blake3,
            ContentHashAlgorithm::Sha256 => Self::Sha256,
        }
    }
}

impl From<HashAlgorithmDocument> for ContentHashAlgorithm {
    fn from(value: HashAlgorithmDocument) -> Self {
        match value {
            HashAlgorithmDocument::Blake3 => Self::Blake3,
            HashAlgorithmDocument::Sha256 => Self::Sha256,
        }
    }
}

impl TryFrom<&BackupSnapshot> for BackupSnapshotDocument {
    type Error = BackupRepositoryError;

    fn try_from(value: &BackupSnapshot) -> Result<Self, Self::Error> {
        Ok(Self {
            source_revision: FileRevisionDocument::try_from(value.source_revision())?,
            content_hash: value.content_hash().into(),
            content_kind: value.content_kind().into(),
            original_bytes: u64_to_i64(value.original_bytes(), "snapshot.original_bytes")?,
            stored_bytes: u64_to_i64(value.stored_bytes(), "snapshot.stored_bytes")?,
            compression: value.compression().into(),
        })
    }
}

impl TryFrom<BackupSnapshotDocument> for BackupSnapshot {
    type Error = BackupRepositoryError;

    fn try_from(value: BackupSnapshotDocument) -> Result<Self, Self::Error> {
        BackupSnapshot::new(
            FileRevision::try_from(value.source_revision)?,
            FileContentHash::try_from(value.content_hash)?,
            value.content_kind.into(),
            i64_to_u64(value.original_bytes, "snapshot.original_bytes")?,
            i64_to_u64(value.stored_bytes, "snapshot.stored_bytes")?,
            value.compression.into(),
        )
        .map_err(invalid_domain)
    }
}

impl From<FileContentKind> for ContentKindDocument {
    fn from(value: FileContentKind) -> Self {
        match value {
            FileContentKind::Text => Self::Text,
            FileContentKind::Binary => Self::Binary,
        }
    }
}

impl From<ContentKindDocument> for FileContentKind {
    fn from(value: ContentKindDocument) -> Self {
        match value {
            ContentKindDocument::Text => Self::Text,
            ContentKindDocument::Binary => Self::Binary,
        }
    }
}

impl From<SnapshotCompression> for CompressionDocument {
    fn from(value: SnapshotCompression) -> Self {
        match value {
            SnapshotCompression::None => Self::None,
            SnapshotCompression::Gzip => Self::Gzip,
        }
    }
}

impl From<CompressionDocument> for SnapshotCompression {
    fn from(value: CompressionDocument) -> Self {
        match value {
            CompressionDocument::None => Self::None,
            CompressionDocument::Gzip => Self::Gzip,
        }
    }
}

impl From<BackupState> for BackupStateDocument {
    fn from(value: BackupState) -> Self {
        match value {
            BackupState::Preparing { lease_expires_at } => Self::Preparing {
                lease_expires_at: to_bson_datetime(lease_expires_at),
            },
            BackupState::Available => Self::Available,
            BackupState::Restoring { lease_expires_at } => Self::Restoring {
                lease_expires_at: to_bson_datetime(lease_expires_at),
            },
            BackupState::Deleting { lease_expires_at } => Self::Deleting {
                lease_expires_at: to_bson_datetime(lease_expires_at),
            },
            BackupState::PreparationFailed => Self::PreparationFailed,
        }
    }
}

impl TryFrom<BackupStateDocument> for BackupState {
    type Error = BackupRepositoryError;

    fn try_from(value: BackupStateDocument) -> Result<Self, Self::Error> {
        Ok(match value {
            BackupStateDocument::Preparing { lease_expires_at } => Self::Preparing {
                lease_expires_at: from_bson_datetime(lease_expires_at)?,
            },
            BackupStateDocument::Available => Self::Available,
            BackupStateDocument::Restoring { lease_expires_at } => Self::Restoring {
                lease_expires_at: from_bson_datetime(lease_expires_at)?,
            },
            BackupStateDocument::Deleting { lease_expires_at } => Self::Deleting {
                lease_expires_at: from_bson_datetime(lease_expires_at)?,
            },
            BackupStateDocument::PreparationFailed => Self::PreparationFailed,
        })
    }
}

impl From<&BackupDiff> for BackupDiffDocument {
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

impl From<BackupDiffDocument> for BackupDiff {
    fn from(value: BackupDiffDocument) -> Self {
        match value {
            BackupDiffDocument::DiffMatchPatch { patch } => Self::DiffMatchPatch(patch),
            BackupDiffDocument::Skipped { reason } => Self::Skipped(reason.into()),
        }
    }
}

impl From<BackupDiffSkipReason> for DiffSkipReasonDocument {
    fn from(value: BackupDiffSkipReason) -> Self {
        match value {
            BackupDiffSkipReason::BinaryContent => Self::BinaryContent,
            BackupDiffSkipReason::Disabled => Self::Disabled,
            BackupDiffSkipReason::InputTooLarge => Self::InputTooLarge,
            BackupDiffSkipReason::UnsupportedEncoding => Self::UnsupportedEncoding,
            BackupDiffSkipReason::GenerationTimedOut => Self::GenerationTimedOut,
        }
    }
}

impl From<DiffSkipReasonDocument> for BackupDiffSkipReason {
    fn from(value: DiffSkipReasonDocument) -> Self {
        match value {
            DiffSkipReasonDocument::BinaryContent => Self::BinaryContent,
            DiffSkipReasonDocument::Disabled => Self::Disabled,
            DiffSkipReasonDocument::InputTooLarge => Self::InputTooLarge,
            DiffSkipReasonDocument::UnsupportedEncoding => Self::UnsupportedEncoding,
            DiffSkipReasonDocument::GenerationTimedOut => Self::GenerationTimedOut,
        }
    }
}

fn parse_backup_id(value: &str) -> Result<BackupId, BackupRepositoryError> {
    value
        .parse()
        .map_err(|error| invalid_data(format!("invalid backup ID: {error}")))
}

fn parse_mutation_id(value: &str) -> Result<MutationId, BackupRepositoryError> {
    value
        .parse()
        .map_err(|error| invalid_data(format!("invalid mutation ID: {error}")))
}

fn to_bson_datetime(value: DateTime<Utc>) -> BsonDateTime {
    BsonDateTime::from_millis(value.timestamp_millis())
}

fn from_bson_datetime(value: BsonDateTime) -> Result<DateTime<Utc>, BackupRepositoryError> {
    DateTime::from_timestamp_millis(value.timestamp_millis())
        .ok_or_else(|| invalid_data("timestamp is outside the chrono range"))
}

fn u64_to_i64(value: u64, field: &str) -> Result<i64, BackupRepositoryError> {
    i64::try_from(value).map_err(|_| invalid_data(format!("{field} exceeds BSON i64")))
}

fn i64_to_u64(value: i64, field: &str) -> Result<u64, BackupRepositoryError> {
    u64::try_from(value).map_err(|_| invalid_data(format!("{field} cannot be negative")))
}

fn invalid_domain(error: impl std::fmt::Display) -> BackupRepositoryError {
    invalid_data(error.to_string())
}

fn invalid_data(message: impl Into<String>) -> BackupRepositoryError {
    BackupRepositoryError::InvalidData {
        message: message.into(),
    }
}

fn database_error(error: MongoError) -> BackupRepositoryError {
    BackupRepositoryError::Unavailable {
        message: error.to_string(),
    }
}

fn is_duplicate_key(error: &MongoError) -> bool {
    matches!(
        error.kind.as_ref(),
        ErrorKind::Write(WriteFailure::WriteError(error)) if error.code == DUPLICATE_KEY_CODE
    )
}

#[cfg(test)]
mod tests {
    use chrono::{Duration as ChronoDuration, TimeZone};

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000, 123_000_000).unwrap()
    }

    fn available_backup(kind: FileContentKind, diff: BackupDiff) -> Backup {
        let revision = FileRevision::from_metadata(8, now());
        let mut backup = Backup::prepare(
            BackupId::new(),
            MutationId::new(),
            BackupSource::new(
                StorageNamespace::new("configuration").unwrap(),
                RelativeStoragePath::new("scriptfiles/config/server.cfg").unwrap(),
            )
            .unwrap(),
            BackupAction::Overwrite,
            BackupInitiatorId::new(42).unwrap(),
            revision.clone(),
            now(),
            now() + ChronoDuration::days(14),
            now() + ChronoDuration::minutes(5),
        )
        .unwrap();
        let hash = FileContentHash::new(ContentHashAlgorithm::Sha256, "12".repeat(32)).unwrap();
        backup
            .mark_available(
                BackupSnapshot::new(revision, hash, kind, 8, 6, SnapshotCompression::Gzip).unwrap(),
                diff,
            )
            .unwrap();
        backup
    }

    #[test]
    fn round_trips_available_backup_document_without_user_denormalization() {
        let backup = available_backup(
            FileContentKind::Text,
            BackupDiff::DiffMatchPatch("@@ -1 +1 @@".into()),
        );
        let document = BackupDocument::try_from(&backup).unwrap();
        let bson = mongodb::bson::to_document(&document).unwrap();

        assert_eq!(bson["initiated_by"].as_i64(), Some(42));
        assert!(bson.get("username").is_none());
        assert!(bson.get("avatar").is_none());
        assert_eq!(
            bson["state"].as_document().unwrap().get_str("kind"),
            Ok("available")
        );
        assert_eq!(
            bson["diff"].as_document().unwrap().get_str("kind"),
            Ok("diff_match_patch")
        );

        let restored = Backup::try_from(document).unwrap();
        assert_eq!(restored, backup);
    }

    #[test]
    fn round_trips_binary_skip_and_lease_state() {
        let mut backup = available_backup(
            FileContentKind::Binary,
            BackupDiff::Skipped(BackupDiffSkipReason::BinaryContent),
        );
        backup
            .begin_restore(now(), now() + ChronoDuration::minutes(5))
            .unwrap();

        let restored = Backup::try_from(BackupDocument::try_from(&backup).unwrap()).unwrap();
        assert_eq!(restored, backup);
        assert!(matches!(restored.state(), BackupState::Restoring { .. }));
    }

    #[test]
    fn rejects_negative_bson_sizes_and_versions() {
        let backup = available_backup(
            FileContentKind::Text,
            BackupDiff::DiffMatchPatch(String::new()),
        );
        let mut negative_version = BackupDocument::try_from(&backup).unwrap();
        negative_version.version = -1;
        assert!(matches!(
            Backup::try_from(negative_version),
            Err(BackupRepositoryError::InvalidData { .. })
        ));

        let mut negative_size = BackupDocument::try_from(&backup).unwrap();
        negative_size.snapshot.as_mut().unwrap().stored_bytes = -1;
        assert!(matches!(
            Backup::try_from(negative_size),
            Err(BackupRepositoryError::InvalidData { .. })
        ));
    }

    #[test]
    fn rejects_patch_that_could_exceed_mongodb_document_limit() {
        let backup = available_backup(
            FileContentKind::Text,
            BackupDiff::DiffMatchPatch("x".repeat(MAX_INLINE_DIFF_BYTES + 1)),
        );

        assert!(matches!(
            BackupDocument::try_from(&backup),
            Err(BackupRepositoryError::InvalidData { .. })
        ));
    }

    #[test]
    fn backup_list_query_keeps_cursor_timestamps_at_bson_precision() {
        let timestamp = now();
        let bson = to_bson_datetime(timestamp);
        assert_eq!(from_bson_datetime(bson).unwrap(), timestamp);
    }
}
