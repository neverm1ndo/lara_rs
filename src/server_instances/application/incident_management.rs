use std::{future::Future, pin::Pin, sync::Arc};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{incidents::IncidentStoreError, registry::InstanceRegistry};
use crate::{
    server_instances::domain::{
        Incident, IncidentId, IncidentOperationalState, IncidentReviewState, IncidentReviewerId,
        InstanceCapability, InstanceManagement, InvalidIncident, ServerInstanceId,
    },
    shared::user_role::UserRole,
};

const MAX_PAGE_SIZE: usize = 100;
const DEFAULT_PAGE_SIZE: usize = 50;

#[derive(Debug, Clone, Serialize)]
pub struct IncidentFilters {
    pub operational_state: Option<IncidentOperationalState>,
    pub review_state: Option<IncidentReviewState>,
    pub opened_from: Option<DateTime<Utc>>,
    pub opened_to: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct IncidentListRequest {
    pub filters: IncidentFilters,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct IncidentListPage {
    pub items: Vec<Incident>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentListCursor {
    version: u8,
    instance_id: String,
    filters: String,
    pub opened_at_millis: i64,
    pub incident_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewAction {
    Acknowledge,
    Investigate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewResult {
    pub incident_id: IncidentId,
    pub version: u64,
    pub state: IncidentReviewState,
    pub actor_user_id: i64,
    pub note: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewReplay {
    pub fingerprint: String,
    pub result: ReviewResult,
}

pub type ManagementFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, IncidentStoreError>> + Send + 'a>>;

pub trait IncidentManagementStore: Send + Sync {
    fn list<'a>(
        &'a self,
        instance: &'a ServerInstanceId,
        filters: &'a IncidentFilters,
        cursor: Option<&'a IncidentListCursor>,
        limit: usize,
    ) -> ManagementFuture<'a, Vec<Incident>>;
    fn get<'a>(&'a self, id: IncidentId) -> ManagementFuture<'a, Option<Incident>>;
    fn by_review_key<'a>(
        &'a self,
        id: IncidentId,
        actor: i64,
        key: &'a str,
    ) -> ManagementFuture<'a, Option<ReviewReplay>>;
    fn save_review<'a>(
        &'a self,
        incident: &'a Incident,
        expected_version: u64,
        actor: i64,
        key: &'a str,
        replay: &'a ReviewReplay,
    ) -> ManagementFuture<'a, ()>;
}

pub struct IncidentManagementService {
    registry: Arc<dyn InstanceRegistry>,
    store: Arc<dyn IncidentManagementStore>,
}

impl IncidentManagementService {
    pub fn new(
        registry: Arc<dyn InstanceRegistry>,
        store: Arc<dyn IncidentManagementStore>,
    ) -> Self {
        Self { registry, store }
    }

    pub fn authorize(
        &self,
        role: UserRole,
        permissions: &[UserRole],
        instance: &ServerInstanceId,
    ) -> Result<(), ManagementError> {
        let Some(descriptor) = self.registry.get(instance) else {
            return Err(ManagementError::NotFound);
        };
        let developer = role == UserRole::Developer || permissions.contains(&UserRole::Developer);
        if !developer {
            return Err(
                if descriptor.kind() == crate::server_instances::domain::InstanceKind::Primary {
                    ManagementError::Forbidden
                } else {
                    ManagementError::NotFound
                },
            );
        }
        if descriptor.management() != InstanceManagement::Systemd
            || !descriptor
                .capabilities()
                .contains(InstanceCapability::Incidents)
            || !descriptor.observability().incident_tracking()
        {
            return Err(ManagementError::NotFound);
        }
        Ok(())
    }

    pub async fn list(
        &self,
        role: UserRole,
        permissions: &[UserRole],
        instance: &ServerInstanceId,
        request: IncidentListRequest,
    ) -> Result<IncidentListPage, ManagementError> {
        self.authorize(role, permissions, instance)?;
        let limit = request.limit.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_PAGE_SIZE).contains(&limit)
            || request
                .filters
                .opened_from
                .zip(request.filters.opened_to)
                .is_some_and(|(from, to)| from > to)
        {
            return Err(ManagementError::BadRequest);
        }
        let filter_hash = filters_hash(&request.filters)?;
        let cursor = request
            .cursor
            .as_deref()
            .map(|token| decode_cursor(token, instance, &filter_hash))
            .transpose()?;
        let mut items = self
            .store
            .list(instance, &request.filters, cursor.as_ref(), limit + 1)
            .await?;
        let next_cursor = if items.len() > limit {
            items.truncate(limit);
            let last = items.last().expect("nonzero page size");
            Some(encode_cursor(IncidentListCursor {
                version: 1,
                instance_id: instance.to_string(),
                filters: filter_hash,
                opened_at_millis: last.opened_at().timestamp_millis(),
                incident_id: last.id().to_string(),
            })?)
        } else {
            None
        };
        Ok(IncidentListPage { items, next_cursor })
    }

    pub async fn get(
        &self,
        role: UserRole,
        permissions: &[UserRole],
        instance: &ServerInstanceId,
        id: IncidentId,
    ) -> Result<Incident, ManagementError> {
        self.authorize(role, permissions, instance)?;
        let incident = self.store.get(id).await?.ok_or(ManagementError::NotFound)?;
        if incident.instance_id() != instance {
            return Err(ManagementError::NotFound);
        }
        Ok(incident)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn review(
        &self,
        role: UserRole,
        permissions: &[UserRole],
        instance: &ServerInstanceId,
        id: IncidentId,
        actor: i64,
        key: &str,
        expected_version: u64,
        action: ReviewAction,
        note: String,
    ) -> Result<ReviewResult, ManagementError> {
        self.authorize(role, permissions, instance)?;
        let actor_id = IncidentReviewerId::new(actor).map_err(|_| ManagementError::BadRequest)?;
        let fingerprint = review_fingerprint(expected_version, action, &note);
        let mut incident = self.get(role, permissions, instance, id).await?;
        if let Some(replay) = self.store.by_review_key(id, actor, key).await? {
            return if replay.fingerprint == fingerprint {
                Ok(replay.result)
            } else {
                Err(ManagementError::Conflict)
            };
        }
        if note.trim().is_empty() || note.len() > 1000 {
            return Err(ManagementError::BadRequest);
        }
        if incident.version() != expected_version {
            return Err(ManagementError::PreconditionFailed);
        }
        let at = Utc::now().max(incident.updated_at());
        match action {
            ReviewAction::Acknowledge => incident.acknowledge(actor_id, &note, at),
            ReviewAction::Investigate => incident.investigate(actor_id, &note, at),
        }
        .map_err(|error| match error {
            InvalidIncident::Transition => ManagementError::Conflict,
            InvalidIncident::ReviewNote => ManagementError::BadRequest,
            _ => ManagementError::Unavailable,
        })?;
        let result = ReviewResult {
            incident_id: id,
            version: incident.version(),
            state: incident.review_state(),
            actor_user_id: actor,
            note,
            updated_at: at,
        };
        let replay = ReviewReplay {
            fingerprint,
            result: result.clone(),
        };
        match self
            .store
            .save_review(&incident, expected_version, actor, key, &replay)
            .await
        {
            Ok(()) => Ok(result),
            Err(IncidentStoreError::ConcurrentModification) => {
                if let Some(saved) = self.store.by_review_key(id, actor, key).await? {
                    if saved.fingerprint == replay.fingerprint {
                        Ok(saved.result)
                    } else {
                        Err(ManagementError::Conflict)
                    }
                } else {
                    Err(ManagementError::PreconditionFailed)
                }
            }
            Err(error) => Err(error.into()),
        }
    }
}

fn filters_hash(filters: &IncidentFilters) -> Result<String, ManagementError> {
    let bytes = serde_json::to_vec(filters).map_err(|_| ManagementError::BadRequest)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn review_fingerprint(version: u64, action: ReviewAction, note: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(version.to_be_bytes());
    digest.update([match action {
        ReviewAction::Acknowledge => 1,
        ReviewAction::Investigate => 2,
    }]);
    digest.update(note.as_bytes());
    format!("{:x}", digest.finalize())
}

fn encode_cursor(cursor: IncidentListCursor) -> Result<String, ManagementError> {
    serde_json::to_vec(&cursor)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| ManagementError::BadRequest)
}

fn decode_cursor(
    token: &str,
    instance: &ServerInstanceId,
    filters: &str,
) -> Result<IncidentListCursor, ManagementError> {
    if token.len() > 1024 {
        return Err(ManagementError::BadRequest);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ManagementError::BadRequest)?;
    let cursor: IncidentListCursor =
        serde_json::from_slice(&bytes).map_err(|_| ManagementError::BadRequest)?;
    if cursor.version != 1
        || cursor.instance_id != instance.as_str()
        || cursor.filters != filters
        || cursor.incident_id.parse::<IncidentId>().is_err()
    {
        return Err(ManagementError::BadRequest);
    }
    Ok(cursor)
}

#[derive(Debug, Error)]
pub enum ManagementError {
    #[error("invalid incident request")]
    BadRequest,
    #[error("developer role required")]
    Forbidden,
    #[error("incident or instance not found")]
    NotFound,
    #[error("review transition or idempotency key conflicts")]
    Conflict,
    #[error("incident version changed")]
    PreconditionFailed,
    #[error("incident store unavailable")]
    Unavailable,
}

impl From<IncidentStoreError> for ManagementError {
    fn from(error: IncidentStoreError) -> Self {
        match error {
            IncidentStoreError::ConcurrentModification => Self::PreconditionFailed,
            IncidentStoreError::FactConflict | IncidentStoreError::ActiveConflict => Self::Conflict,
            IncidentStoreError::InvalidData(_) | IncidentStoreError::Unavailable(_) => {
                Self::Unavailable
            }
        }
    }
}
