use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use crate::server_instances::domain::{
    Incident, IncidentFactId, IncidentId, IncidentKind, IncidentOperationalState,
    IncidentReviewState, ServerInstanceId,
};

pub type IncidentStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, IncidentStoreError>> + Send + 'a>>;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum IncidentStoreError {
    #[error("incident fact belongs to another incident")]
    FactConflict,
    #[error("instance already has an active incident")]
    ActiveConflict,
    #[error("incident was concurrently modified")]
    ConcurrentModification,
    #[error("persisted incident data is invalid: {0}")]
    InvalidData(String),
    #[error("incident store is unavailable: {0}")]
    Unavailable(String),
}

/// The store owns the cross-incident fact constraint; the aggregate only
/// deduplicates facts already attached to one incident.
pub trait IncidentRepository: Send + Sync {
    fn insert<'a>(&'a self, incident: &'a Incident) -> IncidentStoreFuture<'a, ()>;
    fn by_id<'a>(&'a self, id: IncidentId) -> IncidentStoreFuture<'a, Option<Incident>>;
    fn by_fact<'a>(
        &'a self,
        instance_id: &'a ServerInstanceId,
        unit_name: &'a str,
        fact_id: &'a IncidentFactId,
    ) -> IncidentStoreFuture<'a, Option<Incident>>;
    fn active_for_instance<'a>(
        &'a self,
        instance_id: &'a ServerInstanceId,
    ) -> IncidentStoreFuture<'a, Option<Incident>>;
    fn save<'a>(
        &'a self,
        incident: &'a Incident,
        expected_version: u64,
    ) -> IncidentStoreFuture<'a, ()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentOutboxEvent {
    pub event_id: String,
    pub incident_id: IncidentId,
    pub instance_id: ServerInstanceId,
    pub version: u64,
    pub occurred_at: DateTime<Utc>,
    pub kind: IncidentKind,
    pub operational_state: IncidentOperationalState,
    pub review_state: IncidentReviewState,
    pub opened_at: DateTime<Utc>,
    pub recovered_at: Option<DateTime<Utc>>,
    pub actor_user_id: Option<i64>,
}

impl IncidentOutboxEvent {
    pub fn from_incident(incident: &Incident) -> Self {
        Self {
            event_id: format!("incident:{}:{}", incident.id(), incident.version()),
            incident_id: incident.id(),
            instance_id: incident.instance_id().clone(),
            version: incident.version(),
            occurred_at: incident.updated_at(),
            kind: incident.kind(),
            operational_state: incident.operational_state(),
            review_state: incident.review_state(),
            opened_at: incident.opened_at(),
            recovered_at: incident.recovered_at(),
            actor_user_id: incident.last_change_actor().map(|actor| actor.get()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedIncidentEvent {
    pub event: IncidentOutboxEvent,
    pub lease_token: String,
}

pub trait IncidentOutbox: Send + Sync {
    fn claim_next<'a>(
        &'a self,
        now: DateTime<Utc>,
        lease_until: DateTime<Utc>,
        lease_token: &'a str,
    ) -> IncidentStoreFuture<'a, Option<ClaimedIncidentEvent>>;
    fn acknowledge<'a>(&'a self, claim: &'a ClaimedIncidentEvent) -> IncidentStoreFuture<'a, ()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalCheckpoint {
    pub instance_id: ServerInstanceId,
    pub boot_id: Uuid,
    pub cursor: String,
    pub version: u64,
}

impl JournalCheckpoint {
    pub fn new(
        instance_id: ServerInstanceId,
        boot_id: Uuid,
        cursor: impl Into<String>,
        version: u64,
    ) -> Result<Self, IncidentStoreError> {
        let cursor = cursor.into();
        IncidentFactId::journal(boot_id, cursor.clone())
            .map_err(|error| IncidentStoreError::InvalidData(error.to_string()))?;
        Ok(Self {
            instance_id,
            boot_id,
            cursor,
            version,
        })
    }
}

/// Call `advance` only after all effects of the journal entry have been durably
/// recorded. A crash before this CAS causes safe replay of the entry.
pub trait IncidentCheckpointRepository: Send + Sync {
    fn by_instance<'a>(
        &'a self,
        instance_id: &'a ServerInstanceId,
    ) -> IncidentStoreFuture<'a, Option<JournalCheckpoint>>;
    fn advance<'a>(
        &'a self,
        checkpoint: &'a JournalCheckpoint,
        expected_version: Option<u64>,
    ) -> IncidentStoreFuture<'a, ()>;
    fn record_gap<'a>(&'a self, gap: &'a JournalGap) -> IncidentStoreFuture<'a, ()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalGap {
    pub instance_id: ServerInstanceId,
    pub previous_cursor: Option<String>,
    pub reason: JournalGapReason,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalGapReason {
    CursorExpired,
    ReadFailure,
    PersistentStorageMissing,
}
