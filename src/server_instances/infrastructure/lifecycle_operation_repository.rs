use std::fmt;

use chrono::{DateTime, Utc};
use mongodb::{
    Collection, Database, IndexModel,
    bson::{self, Bson, DateTime as BsonDateTime, doc},
    error::{Error as MongoError, ErrorKind, WriteFailure},
    options::{IndexOptions, ReturnDocument},
};
use serde::{Deserialize, Serialize};

use crate::server_instances::{
    application::lifecycle_events::{
        ClaimedLifecycleEvent, LifecycleEventOutbox, LifecycleEventOutboxError,
        LifecycleEventOutboxFuture, LifecycleOperationUpdatedEvent,
    },
    application::lifecycle_operations::{
        LifecycleOperationListQuery, LifecycleOperationRepository,
        LifecycleOperationRepositoryError, LifecycleOperationRepositoryFuture,
    },
    domain::{
        IdempotencyKey, LifecycleAction, LifecycleActorId, LifecycleExpectedState,
        LifecycleFailureCode, LifecycleOperation, LifecycleOperationEvidence, LifecycleOperationId,
        LifecycleOperationState, LifecycleOperationVersion, ObservationStatus, ProcessState,
        ReadinessStatus, RequestFingerprint, ServerInstanceId, SystemdJobReference,
    },
};

const COLLECTION: &str = "server_instance_operations";
const DUPLICATE_KEY_CODE: i32 = 11_000;

#[derive(Debug, Clone)]
pub struct MongoLifecycleOperationRepository {
    operations: Collection<LifecycleOperationDocument>,
}

impl MongoLifecycleOperationRepository {
    pub fn new(database: Database) -> Self {
        Self {
            operations: database.collection(COLLECTION),
        }
    }

    pub async fn ensure_indexes(&self) -> Result<(), LifecycleOperationRepositoryError> {
        let idempotency = IndexModel::builder()
            .keys(doc! { "actor_id": 1, "idempotency_key": 1 })
            .options(
                IndexOptions::builder()
                    .name(Some("operations_actor_idempotency_unique".into()))
                    .unique(Some(true))
                    .build(),
            )
            .build();
        let active_instance = IndexModel::builder()
            .keys(doc! { "active_instance_id": 1 })
            .options(
                IndexOptions::builder()
                    .name(Some("operations_active_instance_unique".into()))
                    .unique(Some(true))
                    .partial_filter_expression(Some(
                        doc! { "active_instance_id": { "$exists": true } },
                    ))
                    .build(),
            )
            .build();
        let history = IndexModel::builder()
            .keys(doc! { "instance_id": 1, "created_at": -1, "_id": -1 })
            .options(
                IndexOptions::builder()
                    .name(Some("operations_instance_history".into()))
                    .build(),
            )
            .build();
        let reconciliation = IndexModel::builder()
            .keys(doc! { "active_instance_id": 1, "deadline": 1 })
            .options(
                IndexOptions::builder()
                    .name(Some("operations_active_deadline".into()))
                    .build(),
            )
            .build();
        let outbox = IndexModel::builder()
            .keys(doc! { "outbox.lease_until": 1, "outbox.event_id": 1 })
            .options(
                IndexOptions::builder()
                    .name(Some("operations_embedded_outbox".into()))
                    .build(),
            )
            .build();

        self.operations
            .create_indexes([
                idempotency,
                active_instance,
                history,
                reconciliation,
                outbox,
            ])
            .await
            .map_err(database_error)?;
        Ok(())
    }

    /// Reconstructs the latest event for records written by a binary that did
    /// not yet maintain the embedded outbox. The version marker prevents an
    /// already delivered event from being recreated on every restart.
    pub async fn recover_missing_events(&self) -> Result<u64, LifecycleOperationRepositoryError> {
        let mut cursor = self
            .operations
            .find(doc! {
                "$expr": {
                    "$lt": [
                        { "$ifNull": ["$event_version", -1_i64] },
                        "$version"
                    ]
                }
            })
            .await
            .map_err(database_error)?;
        let mut recovered = 0_u64;
        while cursor.advance().await.map_err(database_error)? {
            let document = cursor.deserialize_current().map_err(database_error)?;
            let operation = LifecycleOperation::try_from(document)?;
            let event = LifecycleOutboxEventDocument::try_from(
                &LifecycleOperationUpdatedEvent::from_operation(&operation),
            )?;
            let version = u64_to_i64(operation.version().get(), "version")?;
            let result = self
                .operations
                .update_one(
                    doc! {
                        "_id": operation.id().to_string(),
                        "version": version,
                        "$expr": {
                            "$lt": [
                                { "$ifNull": ["$event_version", -1_i64] },
                                "$version"
                            ]
                        }
                    },
                    doc! {
                        "$set": { "event_version": version },
                        "$push": { "outbox": event_to_bson(event)? }
                    },
                )
                .await
                .map_err(database_error)?;
            recovered += result.modified_count;
        }
        Ok(recovered)
    }
}

impl LifecycleOperationRepository for MongoLifecycleOperationRepository {
    fn insert<'a>(
        &'a self,
        operation: &'a LifecycleOperation,
    ) -> LifecycleOperationRepositoryFuture<'a, ()> {
        Box::pin(async move {
            let document = LifecycleOperationDocument::try_from(operation)?;
            match self.operations.insert_one(document).await {
                Ok(_) => Ok(()),
                Err(error) if is_duplicate_key(&error) => {
                    Err(LifecycleOperationRepositoryError::AlreadyExists)
                }
                Err(error) => Err(database_error(error)),
            }
        })
    }

    fn find_by_id<'a>(
        &'a self,
        operation_id: LifecycleOperationId,
    ) -> LifecycleOperationRepositoryFuture<'a, Option<LifecycleOperation>> {
        Box::pin(async move {
            self.operations
                .find_one(doc! { "_id": operation_id.to_string() })
                .await
                .map_err(database_error)?
                .map(LifecycleOperation::try_from)
                .transpose()
        })
    }

    fn find_by_idempotency_key<'a>(
        &'a self,
        actor_id: LifecycleActorId,
        idempotency_key: &'a IdempotencyKey,
    ) -> LifecycleOperationRepositoryFuture<'a, Option<LifecycleOperation>> {
        Box::pin(async move {
            self.operations
                .find_one(doc! {
                    "actor_id": actor_id.get(),
                    "idempotency_key": idempotency_key.as_str()
                })
                .await
                .map_err(database_error)?
                .map(LifecycleOperation::try_from)
                .transpose()
        })
    }

    fn find_active_for_instance<'a>(
        &'a self,
        instance_id: &'a ServerInstanceId,
    ) -> LifecycleOperationRepositoryFuture<'a, Option<LifecycleOperation>> {
        Box::pin(async move {
            self.operations
                .find_one(doc! { "active_instance_id": instance_id.as_str() })
                .await
                .map_err(database_error)?
                .map(LifecycleOperation::try_from)
                .transpose()
        })
    }

    fn list_for_instance<'a>(
        &'a self,
        instance_id: &'a ServerInstanceId,
        query: LifecycleOperationListQuery,
    ) -> LifecycleOperationRepositoryFuture<'a, Vec<LifecycleOperation>> {
        Box::pin(async move {
            if query.limit == 0 {
                return Err(invalid_data("query limit must be greater than zero"));
            }
            let mut filter = doc! { "instance_id": instance_id.as_str() };
            if let Some(cursor) = query.cursor {
                let created_at = to_bson_datetime(cursor.created_at);
                filter.insert(
                    "$or",
                    vec![
                        doc! { "created_at": { "$lt": created_at } },
                        doc! {
                            "created_at": created_at,
                            "_id": { "$lt": cursor.operation_id.to_string() }
                        },
                    ],
                );
            }
            let limit =
                i64::try_from(query.limit).map_err(|_| invalid_data("query limit exceeds i64"))?;
            let mut cursor = self
                .operations
                .find(filter)
                .sort(doc! { "created_at": -1, "_id": -1 })
                .limit(limit)
                .await
                .map_err(database_error)?;
            let mut operations = Vec::new();
            while cursor.advance().await.map_err(database_error)? {
                let document = cursor.deserialize_current().map_err(database_error)?;
                operations.push(LifecycleOperation::try_from(document)?);
            }
            Ok(operations)
        })
    }

    fn save<'a>(
        &'a self,
        operation: &'a LifecycleOperation,
        expected_version: LifecycleOperationVersion,
    ) -> LifecycleOperationRepositoryFuture<'a, ()> {
        Box::pin(async move {
            let next = expected_version
                .get()
                .checked_add(1)
                .ok_or_else(|| invalid_data("expected version overflow"))?;
            if operation.version().get() != next {
                return Err(invalid_data(
                    "aggregate version must be exactly one greater than expected version",
                ));
            }
            let canonical = LifecycleOperationDocument::try_from(operation)?;
            let event =
                canonical.outbox.first().cloned().ok_or_else(|| {
                    invalid_data("operation update did not produce an outbox event")
                })?;
            let mut fields = bson::to_document(&canonical).map_err(|error| {
                invalid_data(format!("failed to encode operation update: {error}"))
            })?;
            fields.remove("_id");
            fields.remove("outbox");
            let active = fields.contains_key("active_instance_id");
            let mut update = doc! {
                "$set": fields,
                "$push": { "outbox": event_to_bson(event)? }
            };
            if !active {
                update.insert("$unset", doc! { "active_instance_id": "" });
            }
            let result = self
                .operations
                .update_one(
                    doc! {
                        "_id": operation.id().to_string(),
                        "version": u64_to_i64(expected_version.get(), "version")?
                    },
                    update,
                )
                .await;
            match result {
                Ok(result) if result.matched_count == 0 => {
                    Err(LifecycleOperationRepositoryError::ConcurrentModification)
                }
                Ok(_) => Ok(()),
                Err(error) if is_duplicate_key(&error) => {
                    Err(LifecycleOperationRepositoryError::AlreadyExists)
                }
                Err(error) => Err(database_error(error)),
            }
        })
    }
}

impl LifecycleEventOutbox for MongoLifecycleOperationRepository {
    fn claim_next<'a>(
        &'a self,
        now: DateTime<Utc>,
        lease_until: DateTime<Utc>,
        lease_token: &'a str,
    ) -> LifecycleEventOutboxFuture<'a, Option<ClaimedLifecycleEvent>> {
        Box::pin(async move {
            let document = self
                .operations
                .find_one_and_update(
                    doc! {
                        "outbox.0": { "$exists": true },
                        "$or": [
                            { "outbox.0.lease_until": { "$exists": false } },
                            { "outbox.0.lease_until": { "$lte": to_bson_datetime(now) } }
                        ]
                    },
                    doc! {
                        "$set": {
                            "outbox.0.lease_until": to_bson_datetime(lease_until),
                            "outbox.0.lease_token": lease_token
                        },
                        "$inc": { "outbox.0.attempts": 1_i64 }
                    },
                )
                .return_document(ReturnDocument::After)
                .await
                .map_err(outbox_database_error)?;
            let Some(document) = document else {
                return Ok(None);
            };
            let event = document
                .outbox
                .into_iter()
                .find(|event| event.lease_token.as_deref() == Some(lease_token))
                .ok_or_else(|| {
                    LifecycleEventOutboxError::new(
                        "claimed operation does not contain the lease token",
                    )
                })?;
            Ok(Some(ClaimedLifecycleEvent {
                event: LifecycleOperationUpdatedEvent::try_from(event)
                    .map_err(|error| LifecycleEventOutboxError::new(error.to_string()))?,
                lease_token: lease_token.to_owned(),
            }))
        })
    }

    fn acknowledge<'a>(
        &'a self,
        claim: &'a ClaimedLifecycleEvent,
    ) -> LifecycleEventOutboxFuture<'a, ()> {
        Box::pin(async move {
            let result = self
                .operations
                .update_one(
                    doc! {
                        "_id": claim.event.operation_id().to_string(),
                        "outbox": { "$elemMatch": {
                            "event_id": claim.event.event_id(),
                            "lease_token": &claim.lease_token
                        }}
                    },
                    doc! { "$pull": { "outbox": {
                        "event_id": claim.event.event_id(),
                        "lease_token": &claim.lease_token
                    }}},
                )
                .await
                .map_err(outbox_database_error)?;
            if result.modified_count != 1 {
                return Err(LifecycleEventOutboxError::new(
                    "outbox claim was lost before acknowledgement",
                ));
            }
            Ok(())
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct LifecycleOperationDocument {
    #[serde(rename = "_id")]
    id: String,
    instance_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_instance_id: Option<String>,
    action: ActionDocument,
    actor_id: i64,
    actor_display_name: String,
    idempotency_key: String,
    request_fingerprint: String,
    expected_state: ExpectedStateDocument,
    initial_evidence: EvidenceDocument,
    #[serde(default)]
    final_evidence: Option<EvidenceDocument>,
    state: StateDocument,
    created_at: BsonDateTime,
    updated_at: BsonDateTime,
    deadline: BsonDateTime,
    #[serde(default)]
    completed_at: Option<BsonDateTime>,
    version: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event_version: Option<i64>,
    #[serde(default)]
    outbox: Vec<LifecycleOutboxEventDocument>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct LifecycleOutboxEventDocument {
    event_id: String,
    sequence: i64,
    occurred_at: BsonDateTime,
    instance_id: String,
    operation_id: String,
    action: ActionDocument,
    actor_id: i64,
    actor_display_name: String,
    state: StateDocument,
    deadline: BsonDateTime,
    #[serde(default)]
    completed_at: Option<BsonDateTime>,
    attempts: i64,
    #[serde(default)]
    lease_until: Option<BsonDateTime>,
    #[serde(default)]
    lease_token: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ActionDocument {
    Start,
    Stop,
    Restart,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedStateDocument {
    Active,
    Inactive,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct EvidenceDocument {
    process: ProcessStateDocument,
    readiness: ReadinessStatusDocument,
    observation: ObservationStatusDocument,
    #[serde(default)]
    observed_at: Option<BsonDateTime>,
    #[serde(default)]
    restart_count: Option<i64>,
    #[serde(default)]
    invocation_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProcessStateDocument {
    Unknown,
    Inactive,
    Activating,
    Active,
    Deactivating,
    Failed,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReadinessStatusDocument {
    Unknown,
    NotReady,
    Ready,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ObservationStatusDocument {
    NotObserved,
    Observed,
    Stale,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StateDocument {
    Requested,
    Dispatching,
    WaitingForState { systemd_job: String },
    Succeeded,
    Failed { code: FailureCodeDocument },
    TimedOut,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum FailureCodeDocument {
    RuntimeUnavailable,
    RuntimeRejected,
    ObservationUnavailable,
    UnexpectedFinalState,
    ReconciliationFailed,
}

impl TryFrom<&LifecycleOperation> for LifecycleOperationDocument {
    type Error = LifecycleOperationRepositoryError;

    fn try_from(operation: &LifecycleOperation) -> Result<Self, Self::Error> {
        let event = LifecycleOperationUpdatedEvent::from_operation(operation);
        Ok(Self {
            id: operation.id().to_string(),
            instance_id: operation.instance_id().to_string(),
            active_instance_id: (!operation.state().is_terminal())
                .then(|| operation.instance_id().to_string()),
            action: operation.action().into(),
            actor_id: operation.actor_id().get(),
            actor_display_name: operation.actor_display_name().to_owned(),
            idempotency_key: operation.idempotency_key().as_str().to_owned(),
            request_fingerprint: operation.request_fingerprint().as_str().to_owned(),
            expected_state: operation.expected_state().into(),
            initial_evidence: EvidenceDocument::try_from(operation.initial_evidence())?,
            final_evidence: operation
                .final_evidence()
                .map(EvidenceDocument::try_from)
                .transpose()?,
            state: StateDocument::from(operation.state()),
            created_at: to_bson_datetime(operation.created_at()),
            updated_at: to_bson_datetime(operation.updated_at()),
            deadline: to_bson_datetime(operation.deadline()),
            completed_at: operation.completed_at().map(to_bson_datetime),
            version: u64_to_i64(operation.version().get(), "version")?,
            event_version: Some(u64_to_i64(operation.version().get(), "event version")?),
            outbox: vec![LifecycleOutboxEventDocument::try_from(&event)?],
        })
    }
}

impl TryFrom<&LifecycleOperationUpdatedEvent> for LifecycleOutboxEventDocument {
    type Error = LifecycleOperationRepositoryError;

    fn try_from(event: &LifecycleOperationUpdatedEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            event_id: event.event_id().to_owned(),
            sequence: u64_to_i64(event.sequence().get(), "event sequence")?,
            occurred_at: to_bson_datetime(event.occurred_at()),
            instance_id: event.instance_id().to_string(),
            operation_id: event.operation_id().to_string(),
            action: event.action().into(),
            actor_id: event.actor_id().get(),
            actor_display_name: event.actor_display_name().to_owned(),
            state: StateDocument::from(event.state()),
            deadline: to_bson_datetime(event.deadline()),
            completed_at: event.completed_at().map(to_bson_datetime),
            attempts: 0,
            lease_until: None,
            lease_token: None,
        })
    }
}

impl TryFrom<LifecycleOutboxEventDocument> for LifecycleOperationUpdatedEvent {
    type Error = LifecycleOperationRepositoryError;

    fn try_from(event: LifecycleOutboxEventDocument) -> Result<Self, Self::Error> {
        LifecycleOperationUpdatedEvent::rehydrate(
            event.event_id,
            LifecycleOperationVersion::from_value(i64_to_u64(event.sequence, "event sequence")?),
            from_bson_datetime(event.occurred_at)?,
            ServerInstanceId::new(event.instance_id).map_err(invalid_domain)?,
            event
                .operation_id
                .parse()
                .map_err(|error| invalid_data(format!("invalid event operation ID: {error}")))?,
            event.action.into(),
            LifecycleActorId::new(event.actor_id).map_err(invalid_domain)?,
            event.actor_display_name,
            LifecycleOperationState::try_from(event.state)?,
            from_bson_datetime(event.deadline)?,
            event.completed_at.map(from_bson_datetime).transpose()?,
        )
        .map_err(invalid_domain)
    }
}

impl TryFrom<LifecycleOperationDocument> for LifecycleOperation {
    type Error = LifecycleOperationRepositoryError;

    fn try_from(document: LifecycleOperationDocument) -> Result<Self, Self::Error> {
        if document
            .event_version
            .is_some_and(|event_version| event_version > document.version)
        {
            return Err(invalid_data(
                "event version cannot be ahead of the canonical operation",
            ));
        }
        let state = LifecycleOperationState::try_from(document.state)?;
        let expected_active_marker =
            (!state.is_terminal()).then_some(document.instance_id.as_str());
        if document.active_instance_id.as_deref() != expected_active_marker {
            return Err(invalid_data(
                "active instance marker does not match operation state",
            ));
        }
        LifecycleOperation::rehydrate(
            document
                .id
                .parse()
                .map_err(|error| invalid_data(format!("invalid operation ID: {error}")))?,
            ServerInstanceId::new(document.instance_id).map_err(invalid_domain)?,
            document.action.into(),
            LifecycleActorId::new(document.actor_id).map_err(invalid_domain)?,
            document.actor_display_name,
            IdempotencyKey::new(document.idempotency_key).map_err(invalid_domain)?,
            RequestFingerprint::new(document.request_fingerprint).map_err(invalid_domain)?,
            document.expected_state.into(),
            LifecycleOperationEvidence::try_from(document.initial_evidence)?,
            document
                .final_evidence
                .map(LifecycleOperationEvidence::try_from)
                .transpose()?,
            state,
            from_bson_datetime(document.created_at)?,
            from_bson_datetime(document.updated_at)?,
            from_bson_datetime(document.deadline)?,
            document.completed_at.map(from_bson_datetime).transpose()?,
            LifecycleOperationVersion::from_value(i64_to_u64(document.version, "version")?),
        )
        .map_err(invalid_domain)
    }
}

impl TryFrom<&LifecycleOperationEvidence> for EvidenceDocument {
    type Error = LifecycleOperationRepositoryError;

    fn try_from(value: &LifecycleOperationEvidence) -> Result<Self, Self::Error> {
        Ok(Self {
            process: value.process().into(),
            readiness: value.readiness().into(),
            observation: value.observation().into(),
            observed_at: value.observed_at().map(to_bson_datetime),
            restart_count: value.restart_count().map(i64::from),
            invocation_id: value.invocation_id().map(str::to_owned),
        })
    }
}

impl TryFrom<EvidenceDocument> for LifecycleOperationEvidence {
    type Error = LifecycleOperationRepositoryError;

    fn try_from(value: EvidenceDocument) -> Result<Self, Self::Error> {
        Ok(Self::new(
            value.process.into(),
            value.readiness.into(),
            value.observation.into(),
            value.observed_at.map(from_bson_datetime).transpose()?,
            value
                .restart_count
                .map(|count| {
                    u32::try_from(count)
                        .map_err(|_| invalid_data("restart count is outside the u32 range"))
                })
                .transpose()?,
            value.invocation_id,
        ))
    }
}

impl From<LifecycleAction> for ActionDocument {
    fn from(value: LifecycleAction) -> Self {
        match value {
            LifecycleAction::Start => Self::Start,
            LifecycleAction::Stop => Self::Stop,
            LifecycleAction::Restart => Self::Restart,
        }
    }
}

impl From<ActionDocument> for LifecycleAction {
    fn from(value: ActionDocument) -> Self {
        match value {
            ActionDocument::Start => Self::Start,
            ActionDocument::Stop => Self::Stop,
            ActionDocument::Restart => Self::Restart,
        }
    }
}

impl From<LifecycleExpectedState> for ExpectedStateDocument {
    fn from(value: LifecycleExpectedState) -> Self {
        match value {
            LifecycleExpectedState::Active => Self::Active,
            LifecycleExpectedState::Inactive => Self::Inactive,
        }
    }
}

impl From<ExpectedStateDocument> for LifecycleExpectedState {
    fn from(value: ExpectedStateDocument) -> Self {
        match value {
            ExpectedStateDocument::Active => Self::Active,
            ExpectedStateDocument::Inactive => Self::Inactive,
        }
    }
}

impl From<ProcessState> for ProcessStateDocument {
    fn from(value: ProcessState) -> Self {
        match value {
            ProcessState::Unknown => Self::Unknown,
            ProcessState::Inactive => Self::Inactive,
            ProcessState::Activating => Self::Activating,
            ProcessState::Active => Self::Active,
            ProcessState::Deactivating => Self::Deactivating,
            ProcessState::Failed => Self::Failed,
        }
    }
}

impl From<ProcessStateDocument> for ProcessState {
    fn from(value: ProcessStateDocument) -> Self {
        match value {
            ProcessStateDocument::Unknown => Self::Unknown,
            ProcessStateDocument::Inactive => Self::Inactive,
            ProcessStateDocument::Activating => Self::Activating,
            ProcessStateDocument::Active => Self::Active,
            ProcessStateDocument::Deactivating => Self::Deactivating,
            ProcessStateDocument::Failed => Self::Failed,
        }
    }
}

impl From<ReadinessStatus> for ReadinessStatusDocument {
    fn from(value: ReadinessStatus) -> Self {
        match value {
            ReadinessStatus::Unknown => Self::Unknown,
            ReadinessStatus::NotReady => Self::NotReady,
            ReadinessStatus::Ready => Self::Ready,
        }
    }
}

impl From<ReadinessStatusDocument> for ReadinessStatus {
    fn from(value: ReadinessStatusDocument) -> Self {
        match value {
            ReadinessStatusDocument::Unknown => Self::Unknown,
            ReadinessStatusDocument::NotReady => Self::NotReady,
            ReadinessStatusDocument::Ready => Self::Ready,
        }
    }
}

impl From<ObservationStatus> for ObservationStatusDocument {
    fn from(value: ObservationStatus) -> Self {
        match value {
            ObservationStatus::NotObserved => Self::NotObserved,
            ObservationStatus::Observed => Self::Observed,
            ObservationStatus::Stale => Self::Stale,
        }
    }
}

impl From<ObservationStatusDocument> for ObservationStatus {
    fn from(value: ObservationStatusDocument) -> Self {
        match value {
            ObservationStatusDocument::NotObserved => Self::NotObserved,
            ObservationStatusDocument::Observed => Self::Observed,
            ObservationStatusDocument::Stale => Self::Stale,
        }
    }
}

impl From<&LifecycleOperationState> for StateDocument {
    fn from(value: &LifecycleOperationState) -> Self {
        match value {
            LifecycleOperationState::Requested => Self::Requested,
            LifecycleOperationState::Dispatching => Self::Dispatching,
            LifecycleOperationState::WaitingForState { job } => Self::WaitingForState {
                systemd_job: job.as_str().to_owned(),
            },
            LifecycleOperationState::Succeeded => Self::Succeeded,
            LifecycleOperationState::Failed { code } => Self::Failed {
                code: (*code).into(),
            },
            LifecycleOperationState::TimedOut => Self::TimedOut,
        }
    }
}

impl TryFrom<StateDocument> for LifecycleOperationState {
    type Error = LifecycleOperationRepositoryError;

    fn try_from(value: StateDocument) -> Result<Self, Self::Error> {
        Ok(match value {
            StateDocument::Requested => Self::Requested,
            StateDocument::Dispatching => Self::Dispatching,
            StateDocument::WaitingForState { systemd_job } => Self::WaitingForState {
                job: SystemdJobReference::new(systemd_job).map_err(invalid_domain)?,
            },
            StateDocument::Succeeded => Self::Succeeded,
            StateDocument::Failed { code } => Self::Failed { code: code.into() },
            StateDocument::TimedOut => Self::TimedOut,
        })
    }
}

impl From<LifecycleFailureCode> for FailureCodeDocument {
    fn from(value: LifecycleFailureCode) -> Self {
        match value {
            LifecycleFailureCode::RuntimeUnavailable => Self::RuntimeUnavailable,
            LifecycleFailureCode::RuntimeRejected => Self::RuntimeRejected,
            LifecycleFailureCode::ObservationUnavailable => Self::ObservationUnavailable,
            LifecycleFailureCode::UnexpectedFinalState => Self::UnexpectedFinalState,
            LifecycleFailureCode::ReconciliationFailed => Self::ReconciliationFailed,
        }
    }
}

impl From<FailureCodeDocument> for LifecycleFailureCode {
    fn from(value: FailureCodeDocument) -> Self {
        match value {
            FailureCodeDocument::RuntimeUnavailable => Self::RuntimeUnavailable,
            FailureCodeDocument::RuntimeRejected => Self::RuntimeRejected,
            FailureCodeDocument::ObservationUnavailable => Self::ObservationUnavailable,
            FailureCodeDocument::UnexpectedFinalState => Self::UnexpectedFinalState,
            FailureCodeDocument::ReconciliationFailed => Self::ReconciliationFailed,
        }
    }
}

fn to_bson_datetime(value: DateTime<Utc>) -> BsonDateTime {
    BsonDateTime::from_millis(value.timestamp_millis())
}

fn from_bson_datetime(
    value: BsonDateTime,
) -> Result<DateTime<Utc>, LifecycleOperationRepositoryError> {
    DateTime::from_timestamp_millis(value.timestamp_millis())
        .ok_or_else(|| invalid_data("timestamp is outside the chrono range"))
}

fn u64_to_i64(value: u64, field: &str) -> Result<i64, LifecycleOperationRepositoryError> {
    i64::try_from(value).map_err(|_| invalid_data(format!("{field} exceeds BSON i64")))
}

fn i64_to_u64(value: i64, field: &str) -> Result<u64, LifecycleOperationRepositoryError> {
    u64::try_from(value).map_err(|_| invalid_data(format!("{field} cannot be negative")))
}

fn invalid_domain(error: impl fmt::Display) -> LifecycleOperationRepositoryError {
    invalid_data(error.to_string())
}

fn invalid_data(message: impl Into<String>) -> LifecycleOperationRepositoryError {
    LifecycleOperationRepositoryError::InvalidData {
        message: message.into(),
    }
}

fn database_error(error: MongoError) -> LifecycleOperationRepositoryError {
    LifecycleOperationRepositoryError::Unavailable {
        message: error.to_string(),
    }
}

fn outbox_database_error(error: MongoError) -> LifecycleEventOutboxError {
    LifecycleEventOutboxError::new(error.to_string())
}

fn event_to_bson(
    event: LifecycleOutboxEventDocument,
) -> Result<Bson, LifecycleOperationRepositoryError> {
    bson::to_bson(&event)
        .map_err(|error| invalid_data(format!("failed to encode outbox event: {error}")))
}

fn is_duplicate_key(error: &MongoError) -> bool {
    matches!(
        error.kind.as_ref(),
        ErrorKind::Write(WriteFailure::WriteError(error)) if error.code == DUPLICATE_KEY_CODE
    )
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn operation() -> LifecycleOperation {
        let created_at = DateTime::from_timestamp(1_700_000_000, 123_000_000).unwrap();
        LifecycleOperation::request(
            LifecycleOperationId::new(),
            ServerInstanceId::new("test").unwrap(),
            LifecycleAction::Start,
            LifecycleActorId::new(42).unwrap(),
            "Developer",
            IdempotencyKey::new("request-1").unwrap(),
            RequestFingerprint::new("a".repeat(64)).unwrap(),
            LifecycleOperationEvidence::new(
                ProcessState::Inactive,
                ReadinessStatus::NotReady,
                ObservationStatus::Observed,
                Some(created_at),
                Some(1),
                Some("old-invocation".into()),
            ),
            created_at,
            created_at + Duration::seconds(30),
        )
        .unwrap()
    }

    #[test]
    fn document_round_trip_preserves_active_operation() {
        let operation = operation();
        let document = LifecycleOperationDocument::try_from(&operation).unwrap();
        assert_eq!(document.active_instance_id.as_deref(), Some("test"));
        assert_eq!(document.event_version, Some(0));
        assert_eq!(document.outbox.len(), 1);
        assert_eq!(
            document.outbox[0].event_id,
            format!("lifecycle-operation:{}:0", operation.id())
        );

        let restored = LifecycleOperation::try_from(document).unwrap();
        assert_eq!(restored, operation);
    }

    #[test]
    fn terminal_document_releases_instance_serialization_marker() {
        let mut operation = operation();
        operation.begin_dispatch(operation.created_at()).unwrap();
        operation
            .fail(
                LifecycleFailureCode::RuntimeRejected,
                None,
                operation.created_at() + Duration::seconds(1),
            )
            .unwrap();

        let document = LifecycleOperationDocument::try_from(&operation).unwrap();
        assert!(document.active_instance_id.is_none());
        assert_eq!(LifecycleOperation::try_from(document).unwrap(), operation);
    }

    #[test]
    fn rejects_corrupted_active_marker() {
        let operation = operation();
        let mut document = LifecycleOperationDocument::try_from(&operation).unwrap();
        document.active_instance_id = None;
        assert!(LifecycleOperation::try_from(document).is_err());
    }

    #[test]
    fn rejects_event_marker_ahead_of_canonical_version() {
        let operation = operation();
        let mut document = LifecycleOperationDocument::try_from(&operation).unwrap();
        document.event_version = Some(1);

        assert!(LifecycleOperation::try_from(document).is_err());
    }
}
