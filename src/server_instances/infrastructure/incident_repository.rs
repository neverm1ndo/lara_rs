use chrono::{DateTime, Utc};
use mongodb::{
    Collection, Database, IndexModel,
    bson::{self, DateTime as BsonDateTime, doc},
    error::{Error as MongoError, ErrorKind, WriteFailure},
    options::{IndexOptions, ReturnDocument},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::server_instances::{
    application::incidents::{
        ClaimedIncidentEvent, IncidentCheckpointRepository, IncidentOutbox, IncidentOutboxEvent,
        IncidentRepository, IncidentStoreError, IncidentStoreFuture, JournalCheckpoint, JournalGap,
    },
    domain::{
        Incident, IncidentCause, IncidentConfidence, IncidentEvidence, IncidentFactId, IncidentId,
        IncidentKind, IncidentOperationalState, IncidentReviewEntry, IncidentReviewState,
        IncidentReviewerId, IncidentSnapshot, IncidentUnitName, LifecycleOperationId, ProcessState,
        ServerInstanceId, TerminationEvidence, TerminationKind,
    },
};

const INCIDENTS: &str = "server_instance_incidents";
const CHECKPOINTS: &str = "server_instance_incident_checkpoints";
const GAPS: &str = "server_instance_incident_gaps";
const DUPLICATE_KEY: i32 = 11_000;

#[derive(Clone)]
pub struct MongoIncidentRepository {
    incidents: Collection<IncidentDocument>,
    checkpoints: Collection<CheckpointDocument>,
    gaps: Collection<GapDocument>,
}

impl MongoIncidentRepository {
    pub fn new(database: Database) -> Self {
        Self {
            incidents: database.collection(INCIDENTS),
            checkpoints: database.collection(CHECKPOINTS),
            gaps: database.collection(GAPS),
        }
    }

    pub async fn ensure_indexes(&self) -> Result<(), IncidentStoreError> {
        let facts = IndexModel::builder()
            .keys(doc! { "fact_keys": 1 })
            .options(
                IndexOptions::builder()
                    .name(Some("incidents_facts_unique".into()))
                    .unique(Some(true))
                    .build(),
            )
            .build();
        let history = IndexModel::builder()
            .keys(doc! { "instance_id": 1, "opened_at_sort": -1, "_id": -1 })
            .options(
                IndexOptions::builder()
                    .name(Some("incidents_history".into()))
                    .build(),
            )
            .build();
        let active = IndexModel::builder()
            .keys(doc! { "active_instance_id": 1 })
            .options(
                IndexOptions::builder()
                    .name(Some("incidents_active_unique".into()))
                    .unique(Some(true))
                    .partial_filter_expression(Some(
                        doc! { "active_instance_id": { "$exists": true } },
                    ))
                    .build(),
            )
            .build();
        let outbox = IndexModel::builder()
            .keys(doc! { "outbox.0.lease_until": 1, "outbox.0.event_id": 1 })
            .options(
                IndexOptions::builder()
                    .name(Some("incidents_outbox".into()))
                    .build(),
            )
            .build();
        self.incidents
            .create_indexes([facts, history, active, outbox])
            .await
            .map_err(db_error)?;
        // `_id` is the per-instance unique checkpoint index.
        self.checkpoints
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "boot_id": 1 })
                    .options(
                        IndexOptions::builder()
                            .name(Some("incident_checkpoint_boot".into()))
                            .build(),
                    )
                    .build(),
            )
            .await
            .map_err(db_error)?;
        self.gaps
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "instance_id": 1, "detected_at": -1 })
                    .options(
                        IndexOptions::builder()
                            .name(Some("incident_gaps_history".into()))
                            .build(),
                    )
                    .build(),
            )
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn classify_duplicate(
        &self,
        incident: &Incident,
    ) -> Result<IncidentStoreError, IncidentStoreError> {
        for evidence in incident.evidence() {
            if let Some(existing) = self
                .by_fact(
                    incident.instance_id(),
                    incident.unit_name().as_str(),
                    evidence.fact_id(),
                )
                .await?
                && existing.id() != incident.id()
            {
                return Ok(IncidentStoreError::FactConflict);
            }
        }
        if let Some(existing) = self.active_for_instance(incident.instance_id()).await?
            && existing.id() != incident.id()
        {
            return Ok(IncidentStoreError::ActiveConflict);
        }
        Ok(IncidentStoreError::FactConflict)
    }
}

impl IncidentRepository for MongoIncidentRepository {
    fn insert<'a>(&'a self, incident: &'a Incident) -> IncidentStoreFuture<'a, ()> {
        Box::pin(async move {
            let document = IncidentDocument::try_from(incident)?;
            match self.incidents.insert_one(document).await {
                Ok(_) => Ok(()),
                Err(error) if duplicate_key(&error) => {
                    Err(self.classify_duplicate(incident).await?)
                }
                Err(error) => Err(db_error(error)),
            }
        })
    }

    fn by_id<'a>(&'a self, id: IncidentId) -> IncidentStoreFuture<'a, Option<Incident>> {
        Box::pin(async move {
            self.incidents
                .find_one(doc! { "_id": id.to_string() })
                .await
                .map_err(db_error)?
                .map(Incident::try_from)
                .transpose()
        })
    }

    fn by_fact<'a>(
        &'a self,
        instance_id: &'a ServerInstanceId,
        unit_name: &'a str,
        fact_id: &'a IncidentFactId,
    ) -> IncidentStoreFuture<'a, Option<Incident>> {
        Box::pin(async move {
            let key = fact_key(instance_id, unit_name, fact_id);
            self.incidents
                .find_one(doc! { "instance_id": instance_id.as_str(), "fact_keys": key })
                .await
                .map_err(db_error)?
                .map(Incident::try_from)
                .transpose()
        })
    }

    fn active_for_instance<'a>(
        &'a self,
        instance_id: &'a ServerInstanceId,
    ) -> IncidentStoreFuture<'a, Option<Incident>> {
        Box::pin(async move {
            self.incidents
                .find_one(doc! { "active_instance_id": instance_id.as_str() })
                .await
                .map_err(db_error)?
                .map(Incident::try_from)
                .transpose()
        })
    }

    fn save<'a>(
        &'a self,
        incident: &'a Incident,
        expected_version: u64,
    ) -> IncidentStoreFuture<'a, ()> {
        Box::pin(async move {
            if incident.version()
                != expected_version
                    .checked_add(1)
                    .ok_or_else(|| invalid("version overflow"))?
            {
                return Err(invalid("incident version must advance by exactly one"));
            }
            let canonical = IncidentDocument::try_from(incident)?;
            let event = canonical
                .outbox
                .first()
                .ok_or_else(|| invalid("missing outbox event"))?;
            let event = bson::to_bson(event).map_err(|error| invalid(error.to_string()))?;
            let mut fields =
                bson::to_document(&canonical).map_err(|error| invalid(error.to_string()))?;
            fields.remove("_id");
            fields.remove("outbox");
            let active = fields.contains_key("active_instance_id");
            let mut update = doc! { "$set": fields, "$push": { "outbox": event } };
            if !active {
                update.insert("$unset", doc! { "active_instance_id": "" });
            }
            let result = self.incidents.update_one(
                doc! { "_id": incident.id().to_string(), "version": i64_value(expected_version)? },
                update,
            ).await;
            match result {
                Ok(result) if result.matched_count == 0 => {
                    Err(IncidentStoreError::ConcurrentModification)
                }
                Ok(_) => Ok(()),
                Err(error) if duplicate_key(&error) => {
                    Err(self.classify_duplicate(incident).await?)
                }
                Err(error) => Err(db_error(error)),
            }
        })
    }
}

impl IncidentOutbox for MongoIncidentRepository {
    fn claim_next<'a>(
        &'a self,
        now: DateTime<Utc>,
        lease_until: DateTime<Utc>,
        lease_token: &'a str,
    ) -> IncidentStoreFuture<'a, Option<ClaimedIncidentEvent>> {
        Box::pin(async move {
            if lease_until <= now || lease_token.is_empty() {
                return Err(invalid("invalid outbox lease"));
            }
            let document = self
                .incidents
                .find_one_and_update(
                    doc! { "outbox.0": { "$exists": true }, "$or": [
                        { "outbox.0.lease_until": { "$exists": false } },
                        { "outbox.0.lease_until": { "$lte": bson_time(now) } }
                    ] },
                    doc! { "$set": {
                        "outbox.0.lease_until": bson_time(lease_until),
                        "outbox.0.lease_token": lease_token
                    }, "$inc": { "outbox.0.attempts": 1_i64 } },
                )
                .return_document(ReturnDocument::After)
                .await
                .map_err(db_error)?;
            let Some(document) = document else {
                return Ok(None);
            };
            let event = document
                .outbox
                .into_iter()
                .next()
                .ok_or_else(|| invalid("claimed event missing"))?;
            if event.lease_token.as_deref() != Some(lease_token) {
                return Err(invalid("outbox lease token mismatch"));
            }
            Ok(Some(ClaimedIncidentEvent {
                event: IncidentOutboxEvent::try_from(event)?,
                lease_token: lease_token.to_owned(),
            }))
        })
    }

    fn acknowledge<'a>(&'a self, claim: &'a ClaimedIncidentEvent) -> IncidentStoreFuture<'a, ()> {
        Box::pin(async move {
            let result = self
                .incidents
                .update_one(
                    doc! { "_id": claim.event.incident_id.to_string(), "outbox": { "$elemMatch": {
                        "event_id": &claim.event.event_id, "lease_token": &claim.lease_token
                    }}},
                    doc! { "$pull": { "outbox": {
                        "event_id": &claim.event.event_id, "lease_token": &claim.lease_token
                    }}},
                )
                .await
                .map_err(db_error)?;
            if result.modified_count != 1 {
                return Err(IncidentStoreError::ConcurrentModification);
            }
            Ok(())
        })
    }
}

impl IncidentCheckpointRepository for MongoIncidentRepository {
    fn by_instance<'a>(
        &'a self,
        instance_id: &'a ServerInstanceId,
    ) -> IncidentStoreFuture<'a, Option<JournalCheckpoint>> {
        Box::pin(async move {
            self.checkpoints
                .find_one(doc! { "_id": instance_id.as_str() })
                .await
                .map_err(db_error)?
                .map(JournalCheckpoint::try_from)
                .transpose()
        })
    }

    fn advance<'a>(
        &'a self,
        checkpoint: &'a JournalCheckpoint,
        expected_version: Option<u64>,
    ) -> IncidentStoreFuture<'a, ()> {
        Box::pin(async move {
            let expected_next = expected_version.map_or(Some(0), |value| value.checked_add(1));
            if expected_next != Some(checkpoint.version) {
                return Err(invalid("checkpoint version must advance by one"));
            }
            let document = CheckpointDocument::try_from(checkpoint)?;
            if let Some(version) = expected_version {
                let result = self.checkpoints.replace_one(
                    doc! { "_id": checkpoint.instance_id.as_str(), "version": i64_value(version)? },
                    document,
                ).await.map_err(db_error)?;
                if result.matched_count != 1 {
                    return Err(IncidentStoreError::ConcurrentModification);
                }
            } else {
                match self.checkpoints.insert_one(document).await {
                    Ok(_) => {}
                    Err(error) if duplicate_key(&error) => {
                        return Err(IncidentStoreError::ConcurrentModification);
                    }
                    Err(error) => return Err(db_error(error)),
                }
            }
            Ok(())
        })
    }

    fn record_gap<'a>(&'a self, gap: &'a JournalGap) -> IncidentStoreFuture<'a, ()> {
        Box::pin(async move {
            let id = format!(
                "{}:{}:{:?}",
                gap.instance_id,
                gap.previous_cursor.as_deref().unwrap_or("initial"),
                gap.reason
            );
            let document = GapDocument {
                id: format!("{:x}", Sha256::digest(id.as_bytes())),
                instance_id: gap.instance_id.to_string(),
                previous_cursor: gap.previous_cursor.clone(),
                reason: gap.reason,
                detected_at: bson_time(gap.detected_at),
            };
            match self.gaps.insert_one(document).await {
                Ok(_) => Ok(()),
                Err(error) if duplicate_key(&error) => Ok(()),
                Err(error) => Err(db_error(error)),
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GapDocument {
    #[serde(rename = "_id")]
    id: String,
    instance_id: String,
    previous_cursor: Option<String>,
    reason: crate::server_instances::application::incidents::JournalGapReason,
    detected_at: BsonDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IncidentDocument {
    #[serde(rename = "_id")]
    id: String,
    instance_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_instance_id: Option<String>,
    unit_name: String,
    kind: IncidentKind,
    cause: IncidentCause,
    confidence: IncidentConfidence,
    operational_state: IncidentOperationalState,
    review_state: IncidentReviewState,
    opened_at: String,
    opened_at_sort: BsonDateTime,
    recovered_at: Option<String>,
    updated_at: String,
    version: i64,
    evidence: Vec<EvidenceDocument>,
    fact_keys: Vec<String>,
    related_operation_ids: Vec<String>,
    review_history: Vec<ReviewDocument>,
    last_change_actor: Option<i64>,
    #[serde(default)]
    outbox: Vec<EventDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvidenceDocument {
    fact_id: FactDocument,
    unit_name: String,
    occurred_at: String,
    process: ProcessState,
    invocation_id: Option<String>,
    restart_count: Option<i64>,
    termination: Option<TerminationDocument>,
    confidence: IncidentConfidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
enum FactDocument {
    Journal { boot_id: String, cursor: String },
    Live { key: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TerminationDocument {
    kind: TerminationKind,
    status: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReviewDocument {
    reviewer_id: i64,
    state: IncidentReviewState,
    note: String,
    at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EventDocument {
    event_id: String,
    incident_id: String,
    instance_id: String,
    version: i64,
    occurred_at: String,
    kind: IncidentKind,
    operational_state: IncidentOperationalState,
    review_state: IncidentReviewState,
    opened_at: String,
    recovered_at: Option<String>,
    actor_user_id: Option<i64>,
    attempts: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lease_until: Option<BsonDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lease_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckpointDocument {
    #[serde(rename = "_id")]
    instance_id: String,
    boot_id: String,
    cursor: String,
    version: i64,
}

impl TryFrom<&Incident> for IncidentDocument {
    type Error = IncidentStoreError;

    fn try_from(incident: &Incident) -> Result<Self, Self::Error> {
        let evidence = incident
            .evidence()
            .iter()
            .map(EvidenceDocument::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let fact_keys = incident
            .evidence()
            .iter()
            .map(|evidence| {
                fact_key(
                    incident.instance_id(),
                    incident.unit_name().as_str(),
                    evidence.fact_id(),
                )
            })
            .collect();
        let event = EventDocument::try_from(&IncidentOutboxEvent::from_incident(incident))?;
        Ok(Self {
            id: incident.id().to_string(),
            instance_id: incident.instance_id().to_string(),
            active_instance_id: (incident.operational_state()
                != IncidentOperationalState::Resolved)
                .then(|| incident.instance_id().to_string()),
            unit_name: incident.unit_name().as_str().to_owned(),
            kind: incident.kind(),
            cause: incident.cause(),
            confidence: incident.confidence(),
            operational_state: incident.operational_state(),
            review_state: incident.review_state(),
            opened_at: incident.opened_at().to_rfc3339(),
            opened_at_sort: bson_time(incident.opened_at()),
            recovered_at: incident.recovered_at().map(|at| at.to_rfc3339()),
            updated_at: incident.updated_at().to_rfc3339(),
            version: i64_value(incident.version())?,
            evidence,
            fact_keys,
            related_operation_ids: incident
                .related_operation_ids()
                .iter()
                .map(ToString::to_string)
                .collect(),
            review_history: incident
                .review_history()
                .iter()
                .map(ReviewDocument::from)
                .collect(),
            last_change_actor: incident.last_change_actor().map(|id| id.get()),
            outbox: vec![event],
        })
    }
}

impl TryFrom<IncidentDocument> for Incident {
    type Error = IncidentStoreError;

    fn try_from(document: IncidentDocument) -> Result<Self, Self::Error> {
        let instance_id = ServerInstanceId::new(document.instance_id).map_err(domain_error)?;
        let expected_active = (document.operational_state != IncidentOperationalState::Resolved)
            .then_some(instance_id.as_str());
        if document.active_instance_id.as_deref() != expected_active {
            return Err(invalid("active incident marker does not match state"));
        }
        let unit_name = IncidentUnitName::new(document.unit_name).map_err(domain_error)?;
        let evidence = document
            .evidence
            .into_iter()
            .map(IncidentEvidence::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        if evidence.iter().any(|item| item.unit_name() != &unit_name) {
            return Err(invalid("incident unit does not match evidence"));
        }
        let expected_keys: Vec<_> = evidence
            .iter()
            .map(|item| fact_key(&instance_id, unit_name.as_str(), item.fact_id()))
            .collect();
        if document.fact_keys != expected_keys {
            return Err(invalid("incident fact index does not match evidence"));
        }
        let opened_at = parse_time(&document.opened_at)?;
        if document.opened_at_sort != bson_time(opened_at) {
            return Err(invalid("incident history timestamp does not match"));
        }
        Incident::rehydrate(IncidentSnapshot {
            id: parse_id(&document.id)?,
            instance_id,
            kind: document.kind,
            cause: document.cause,
            confidence: document.confidence,
            operational_state: document.operational_state,
            review_state: document.review_state,
            opened_at,
            recovered_at: document
                .recovered_at
                .as_deref()
                .map(parse_time)
                .transpose()?,
            updated_at: parse_time(&document.updated_at)?,
            version: u64_value(document.version)?,
            evidence,
            related_operation_ids: document
                .related_operation_ids
                .iter()
                .map(|id| {
                    id.parse::<LifecycleOperationId>()
                        .map_err(|error| invalid(error.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?,
            review_history: document
                .review_history
                .into_iter()
                .map(IncidentReviewEntry::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            last_change_actor: document
                .last_change_actor
                .map(IncidentReviewerId::new)
                .transpose()
                .map_err(domain_error)?,
        })
        .map_err(domain_error)
    }
}

impl TryFrom<&IncidentEvidence> for EvidenceDocument {
    type Error = IncidentStoreError;

    fn try_from(value: &IncidentEvidence) -> Result<Self, Self::Error> {
        let fact_id = match value.fact_id() {
            IncidentFactId::Journal { boot_id, cursor } => FactDocument::Journal {
                boot_id: boot_id.to_string(),
                cursor: cursor.clone(),
            },
            IncidentFactId::Live { key } => FactDocument::Live { key: key.clone() },
        };
        Ok(Self {
            fact_id,
            unit_name: value.unit_name().as_str().to_owned(),
            occurred_at: value.occurred_at().to_rfc3339(),
            process: value.process(),
            invocation_id: value.invocation_id().map(str::to_owned),
            restart_count: value.restart_count().map(i64::from),
            termination: value.termination().map(|termination| TerminationDocument {
                kind: termination.kind(),
                status: termination.status(),
            }),
            confidence: value.confidence(),
        })
    }
}

impl TryFrom<EvidenceDocument> for IncidentEvidence {
    type Error = IncidentStoreError;

    fn try_from(value: EvidenceDocument) -> Result<Self, Self::Error> {
        let fact_id = match value.fact_id {
            FactDocument::Journal { boot_id, cursor } => IncidentFactId::journal(
                Uuid::parse_str(&boot_id).map_err(|error| invalid(error.to_string()))?,
                cursor,
            )
            .map_err(domain_error)?,
            FactDocument::Live { key } => IncidentFactId::live(key).map_err(domain_error)?,
        };
        IncidentEvidence::new(
            fact_id,
            IncidentUnitName::new(value.unit_name).map_err(domain_error)?,
            parse_time(&value.occurred_at)?,
            value.process,
            value.invocation_id,
            value
                .restart_count
                .map(|count| u32::try_from(count).map_err(|_| invalid("invalid restart count")))
                .transpose()?,
            value
                .termination
                .map(|termination| TerminationEvidence::new(termination.kind, termination.status)),
            value.confidence,
        )
        .map_err(domain_error)
    }
}

impl From<&IncidentReviewEntry> for ReviewDocument {
    fn from(value: &IncidentReviewEntry) -> Self {
        Self {
            reviewer_id: value.reviewer_id().get(),
            state: value.state(),
            note: value.note().to_owned(),
            at: value.at().to_rfc3339(),
        }
    }
}

impl TryFrom<ReviewDocument> for IncidentReviewEntry {
    type Error = IncidentStoreError;

    fn try_from(value: ReviewDocument) -> Result<Self, Self::Error> {
        IncidentReviewEntry::rehydrate(
            IncidentReviewerId::new(value.reviewer_id).map_err(domain_error)?,
            value.state,
            value.note,
            parse_time(&value.at)?,
        )
        .map_err(domain_error)
    }
}

impl TryFrom<&IncidentOutboxEvent> for EventDocument {
    type Error = IncidentStoreError;

    fn try_from(value: &IncidentOutboxEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            event_id: value.event_id.clone(),
            incident_id: value.incident_id.to_string(),
            instance_id: value.instance_id.to_string(),
            version: i64_value(value.version)?,
            occurred_at: value.occurred_at.to_rfc3339(),
            kind: value.kind,
            operational_state: value.operational_state,
            review_state: value.review_state,
            opened_at: value.opened_at.to_rfc3339(),
            recovered_at: value.recovered_at.map(|at| at.to_rfc3339()),
            actor_user_id: value.actor_user_id,
            attempts: 0,
            lease_until: None,
            lease_token: None,
        })
    }
}

impl TryFrom<EventDocument> for IncidentOutboxEvent {
    type Error = IncidentStoreError;

    fn try_from(value: EventDocument) -> Result<Self, Self::Error> {
        let incident_id = parse_id(&value.incident_id)?;
        let version = u64_value(value.version)?;
        if value.event_id != format!("incident:{incident_id}:{version}") {
            return Err(invalid("outbox event ID does not match incident version"));
        }
        if value.actor_user_id.is_some_and(|actor| actor <= 0) {
            return Err(invalid("outbox actor ID must be positive"));
        }
        Ok(Self {
            event_id: value.event_id,
            incident_id,
            instance_id: ServerInstanceId::new(value.instance_id).map_err(domain_error)?,
            version,
            occurred_at: parse_time(&value.occurred_at)?,
            kind: value.kind,
            operational_state: value.operational_state,
            review_state: value.review_state,
            opened_at: parse_time(&value.opened_at)?,
            recovered_at: value.recovered_at.as_deref().map(parse_time).transpose()?,
            actor_user_id: value.actor_user_id,
        })
    }
}

impl TryFrom<&JournalCheckpoint> for CheckpointDocument {
    type Error = IncidentStoreError;

    fn try_from(value: &JournalCheckpoint) -> Result<Self, Self::Error> {
        JournalCheckpoint::new(
            value.instance_id.clone(),
            value.boot_id,
            value.cursor.clone(),
            value.version,
        )?;
        Ok(Self {
            instance_id: value.instance_id.to_string(),
            boot_id: value.boot_id.to_string(),
            cursor: value.cursor.clone(),
            version: i64_value(value.version)?,
        })
    }
}

impl TryFrom<CheckpointDocument> for JournalCheckpoint {
    type Error = IncidentStoreError;

    fn try_from(value: CheckpointDocument) -> Result<Self, Self::Error> {
        JournalCheckpoint::new(
            ServerInstanceId::new(value.instance_id).map_err(domain_error)?,
            Uuid::parse_str(&value.boot_id).map_err(|error| invalid(error.to_string()))?,
            value.cursor,
            u64_value(value.version)?,
        )
    }
}

fn fact_key(instance: &ServerInstanceId, unit: &str, fact: &IncidentFactId) -> String {
    let mut digest = Sha256::new();
    for part in [instance.as_str(), unit] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    match fact {
        IncidentFactId::Journal { boot_id, cursor } => {
            digest.update(b"journal");
            digest.update(boot_id.as_bytes());
            digest.update(cursor.as_bytes());
        }
        IncidentFactId::Live { key } => {
            digest.update(b"live");
            digest.update(key.as_bytes());
        }
    }
    format!("{:x}", digest.finalize())
}

fn bson_time(value: DateTime<Utc>) -> BsonDateTime {
    BsonDateTime::from_millis(value.timestamp_millis())
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, IncidentStoreError> {
    DateTime::parse_from_rfc3339(value)
        .map(|at| at.with_timezone(&Utc))
        .map_err(|error| invalid(format!("invalid timestamp: {error}")))
}

fn parse_id(value: &str) -> Result<IncidentId, IncidentStoreError> {
    value
        .parse()
        .map_err(|error| invalid(format!("invalid incident ID: {error}")))
}

fn i64_value(value: u64) -> Result<i64, IncidentStoreError> {
    i64::try_from(value).map_err(|_| invalid("version exceeds BSON i64"))
}

fn u64_value(value: i64) -> Result<u64, IncidentStoreError> {
    u64::try_from(value).map_err(|_| invalid("version cannot be negative"))
}

fn invalid(message: impl Into<String>) -> IncidentStoreError {
    IncidentStoreError::InvalidData(message.into())
}

fn domain_error(error: impl std::fmt::Display) -> IncidentStoreError {
    invalid(error.to_string())
}

fn db_error(error: MongoError) -> IncidentStoreError {
    IncidentStoreError::Unavailable(error.to_string())
}

fn duplicate_key(error: &MongoError) -> bool {
    matches!(error.kind.as_ref(), ErrorKind::Write(WriteFailure::WriteError(write)) if write.code == DUPLICATE_KEY)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn incident(id: IncidentId) -> Incident {
        let at = DateTime::from_timestamp(1_700_000_000, 123_456_789).unwrap();
        let evidence = IncidentEvidence::new(
            IncidentFactId::journal(Uuid::new_v4(), "s=cursor;i=1").unwrap(),
            IncidentUnitName::new("lara-game@test.service").unwrap(),
            at,
            ProcessState::Failed,
            Some("old-invocation".into()),
            Some(1),
            Some(TerminationEvidence::new(TerminationKind::ExitCode, Some(9))),
            IncidentConfidence::Confirmed,
        )
        .unwrap();
        Incident::open(
            id,
            ServerInstanceId::new("test").unwrap(),
            IncidentKind::Outage,
            evidence,
        )
        .unwrap()
    }

    #[test]
    fn document_round_trip_preserves_precise_evidence_and_review_history() {
        let mut incident = incident(IncidentId::new());
        let at = incident.opened_at();
        incident
            .resolve(
                IncidentEvidence::new(
                    IncidentFactId::live("ready-fact").unwrap(),
                    IncidentUnitName::new("lara-game@test.service").unwrap(),
                    at + chrono::Duration::seconds(5),
                    ProcessState::Active,
                    Some("new-invocation".into()),
                    Some(2),
                    None,
                    IncidentConfidence::Confirmed,
                )
                .unwrap(),
                at + chrono::Duration::seconds(5),
            )
            .unwrap();
        incident
            .acknowledge(
                IncidentReviewerId::new(42).unwrap(),
                "Checked journal",
                at + chrono::Duration::seconds(6),
            )
            .unwrap();

        let document = IncidentDocument::try_from(&incident).unwrap();
        assert_eq!(
            document.outbox[0].event_id,
            format!("incident:{}:2", incident.id())
        );
        assert_eq!(document.fact_keys.len(), 2);
        let bson = bson::to_document(&document).unwrap();
        let decoded: IncidentDocument = bson::from_document(bson).unwrap();
        assert_eq!(Incident::try_from(decoded).unwrap(), incident);
    }

    #[test]
    fn corrupt_fact_index_is_rejected_before_rehydration() {
        let incident = incident(IncidentId::new());
        let mut document = IncidentDocument::try_from(&incident).unwrap();
        document.fact_keys[0] = "wrong".into();
        assert!(Incident::try_from(document).is_err());
    }

    #[test]
    fn checkpoint_round_trip_rejects_invalid_cursor() {
        let instance = ServerInstanceId::new("test").unwrap();
        let checkpoint =
            JournalCheckpoint::new(instance.clone(), Uuid::new_v4(), "s=cursor", 0).unwrap();
        let document = CheckpointDocument::try_from(&checkpoint).unwrap();
        let decoded = JournalCheckpoint::try_from(document).unwrap();
        assert_eq!(decoded, checkpoint);
        assert!(JournalCheckpoint::new(instance, Uuid::new_v4(), "\n", 0).is_err());
    }

    #[tokio::test]
    #[ignore = "requires an isolated MongoDB URI in LARA_TEST_MONGODB_URI"]
    async fn mongo_enforces_fact_uniqueness_cas_outbox_and_checkpoint() {
        let uri = std::env::var("LARA_TEST_MONGODB_URI")
            .expect("set LARA_TEST_MONGODB_URI to an isolated test MongoDB");
        let client = mongodb::Client::with_uri_str(uri).await.unwrap();
        let database = client.database(&format!("lara_incident_test_{}", Uuid::new_v4().simple()));
        let repository = MongoIncidentRepository::new(database.clone());
        repository.ensure_indexes().await.unwrap();

        let first = incident(IncidentId::new());
        let mut competing = first.clone();
        let mut snapshot = competing.snapshot();
        snapshot.id = IncidentId::new();
        competing = Incident::rehydrate(snapshot).unwrap();
        let (left, right) = tokio::join!(repository.insert(&first), repository.insert(&competing));
        assert!(matches!(
            (&left, &right),
            (Ok(()), Err(IncidentStoreError::FactConflict))
                | (Err(IncidentStoreError::FactConflict), Ok(()))
        ));
        let stored = repository
            .by_fact(
                first.instance_id(),
                first.unit_name().as_str(),
                first.evidence()[0].fact_id(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.evidence()[0], first.evidence()[0]);
        let another_outage = incident(IncidentId::new());
        assert_eq!(
            repository.insert(&another_outage).await,
            Err(IncidentStoreError::ActiveConflict)
        );

        let mut next = stored.clone();
        next.resolve(
            IncidentEvidence::new(
                IncidentFactId::live("recovered").unwrap(),
                IncidentUnitName::new("lara-game@test.service").unwrap(),
                stored.opened_at() + chrono::Duration::seconds(10),
                ProcessState::Active,
                Some("new-invocation".into()),
                Some(2),
                None,
                IncidentConfidence::Confirmed,
            )
            .unwrap(),
            stored.opened_at() + chrono::Duration::seconds(10),
        )
        .unwrap();
        repository.save(&next, 0).await.unwrap();
        assert_eq!(
            repository.save(&next, 0).await,
            Err(IncidentStoreError::ConcurrentModification)
        );
        assert_eq!(repository.by_id(next.id()).await.unwrap().unwrap(), next);

        let now = Utc::now();
        let first_claim = repository
            .claim_next(now, now + chrono::Duration::seconds(30), "first-lease")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first_claim.event.version, 0);
        let recovered_claim = repository
            .claim_next(
                now + chrono::Duration::seconds(31),
                now + chrono::Duration::seconds(61),
                "recovered-lease",
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered_claim.event.event_id, first_claim.event.event_id);
        assert_eq!(
            repository.acknowledge(&first_claim).await,
            Err(IncidentStoreError::ConcurrentModification)
        );
        repository.acknowledge(&recovered_claim).await.unwrap();
        let second_claim = repository
            .claim_next(now, now + chrono::Duration::seconds(30), "second-lease")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second_claim.event.version, 1);
        assert_eq!(
            second_claim.event.event_id,
            format!("incident:{}:1", next.id())
        );
        repository.acknowledge(&second_claim).await.unwrap();
        assert!(
            repository
                .claim_next(now, now + chrono::Duration::seconds(30), "third-lease")
                .await
                .unwrap()
                .is_none()
        );
        repository.insert(&another_outage).await.unwrap();
        assert_eq!(
            repository
                .active_for_instance(next.instance_id())
                .await
                .unwrap()
                .unwrap()
                .id(),
            another_outage.id()
        );

        let checkpoint =
            JournalCheckpoint::new(next.instance_id().clone(), Uuid::new_v4(), "s=cursor-1", 0)
                .unwrap();
        IncidentCheckpointRepository::advance(&repository, &checkpoint, None)
            .await
            .unwrap();
        assert_eq!(
            repository.by_instance(next.instance_id()).await.unwrap(),
            Some(checkpoint.clone())
        );
        assert_eq!(
            IncidentCheckpointRepository::advance(&repository, &checkpoint, None).await,
            Err(IncidentStoreError::ConcurrentModification)
        );
        let advanced = JournalCheckpoint::new(
            next.instance_id().clone(),
            checkpoint.boot_id,
            "s=cursor-2",
            1,
        )
        .unwrap();
        IncidentCheckpointRepository::advance(&repository, &advanced, Some(0))
            .await
            .unwrap();
        assert_eq!(
            repository.by_instance(next.instance_id()).await.unwrap(),
            Some(advanced.clone())
        );
        assert_eq!(
            IncidentCheckpointRepository::advance(&repository, &advanced, Some(0)).await,
            Err(IncidentStoreError::ConcurrentModification)
        );
        database.drop().await.unwrap();
    }
}
