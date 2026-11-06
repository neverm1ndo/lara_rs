use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationMutationState {
    Requested,
    Applying,
    Succeeded,
    Failed,
    ReconciliationRequired,
    Reviewed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationReviewAssessment {
    Applied,
    NotApplied,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigurationMutationReview {
    pub reviewer: String,
    pub reason: String,
    pub assessment: ConfigurationReviewAssessment,
    pub observed_source: ConfigurationFileEvidence,
    pub observed_destination: ConfigurationFileEvidence,
    pub evidence_token: String,
    pub reviewed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "detail", rename_all = "snake_case")]
pub enum ConfigurationFileEvidence {
    Absent,
    Hash(String),
    Unavailable(String),
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigurationMutationEvent {
    pub event_id: String,
    pub mutation_id: String,
    pub instance_id: String,
    pub actor_user_id: String,
    pub actor_session_id: Option<String>,
    pub access_level: String,
    pub operation: String,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub previous_hash: Option<String>,
    pub current_hash: Option<String>,
    pub backup_id: Option<String>,
    pub occurred_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigurationMutationRecord {
    #[serde(rename = "_id")]
    pub id: String,
    pub actor_user_id: String,
    pub idempotency_key: String,
    pub fingerprint: String,
    pub instance_id: String,
    pub operation: String,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub expected_hash: Option<String>,
    pub desired_hash: Option<String>,
    pub active_path: Option<String>,
    pub state: ConfigurationMutationState,
    pub created_at: String,
    pub updated_at: String,
    pub event: Option<ConfigurationMutationEvent>,
    pub failure_code: Option<String>,
    pub delivered_at: Option<String>,
    pub delivery_lease_until: Option<String>,
    pub delivery_lease_token: Option<String>,
    #[serde(default)]
    pub review: Option<ConfigurationMutationReview>,
}

#[derive(Debug, Error)]
pub enum ConfigurationMutationLogError {
    #[error("configuration mutation already exists")]
    AlreadyExists,
    #[error("configuration mutation log unavailable: {0}")]
    Unavailable(String),
}

pub type MutationLogFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ConfigurationMutationLogError>> + Send + 'a>>;

pub trait ConfigurationMutationLog: Send + Sync {
    fn reserve<'a>(&'a self, record: &'a ConfigurationMutationRecord) -> MutationLogFuture<'a, ()>;
    fn by_key<'a>(
        &'a self,
        actor: &'a str,
        key: &'a str,
    ) -> MutationLogFuture<'a, Option<ConfigurationMutationRecord>>;
    fn by_id<'a>(
        &'a self,
        id: &'a str,
    ) -> MutationLogFuture<'a, Option<ConfigurationMutationRecord>>;
    fn transition<'a>(
        &'a self,
        id: &'a str,
        from: ConfigurationMutationState,
        next: ConfigurationMutationRecord,
    ) -> MutationLogFuture<'a, bool>;
    fn unresolved<'a>(&'a self) -> MutationLogFuture<'a, Vec<ConfigurationMutationRecord>>;
    fn claim_event<'a>(
        &'a self,
        token: &'a str,
        now: &'a str,
        until: &'a str,
    ) -> MutationLogFuture<'a, Option<ConfigurationMutationRecord>>;
    fn acknowledge_event<'a>(
        &'a self,
        id: &'a str,
        token: &'a str,
        now: &'a str,
    ) -> MutationLogFuture<'a, ()>;
}

pub type ConfigurationDeliveryFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

pub trait ConfigurationEventDelivery: Send + Sync {
    fn deliver<'a>(
        &'a self,
        event: &'a ConfigurationMutationEvent,
    ) -> ConfigurationDeliveryFuture<'a>;
}
