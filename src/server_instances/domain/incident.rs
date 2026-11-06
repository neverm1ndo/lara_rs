use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use super::{
    LifecycleOperationId, ProcessState, ServerInstanceId, TerminationEvidence, TerminationKind,
};

const MAX_JOURNAL_CURSOR_BYTES: usize = 2048;
const MAX_LIVE_FACT_KEY_BYTES: usize = 128;
const MAX_REVIEW_NOTE_BYTES: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IncidentUnitName(String);

impl IncidentUnitName {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidIncident> {
        let value = value.into();
        if !value.ends_with(".service")
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@' | b':')
            })
        {
            return Err(InvalidIncident::UnitName);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IncidentId(Uuid);

impl IncidentId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }
}

impl Default for IncidentId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for IncidentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for IncidentId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IncidentFactId {
    Journal {
        boot_id: Uuid,
        cursor: String,
    },
    /// Assigned by the observation application service and persisted with its
    /// previous-state boundary. It must be reused when that fact is retried.
    Live {
        key: String,
    },
}

impl IncidentFactId {
    pub fn journal(boot_id: Uuid, cursor: impl Into<String>) -> Result<Self, InvalidIncident> {
        let cursor = cursor.into();
        if boot_id.is_nil()
            || cursor.is_empty()
            || cursor.len() > MAX_JOURNAL_CURSOR_BYTES
            || cursor.chars().any(char::is_control)
        {
            return Err(InvalidIncident::FactId);
        }
        Ok(Self::Journal { boot_id, cursor })
    }

    pub fn live(key: impl Into<String>) -> Result<Self, InvalidIncident> {
        let key = key.into();
        if key.is_empty()
            || key.len() > MAX_LIVE_FACT_KEY_BYTES
            || !key.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(InvalidIncident::FactId);
        }
        Ok(Self::Live { key })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentKind {
    Outage,
    UnexpectedRestart,
    UnplannedStop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentOperationalState {
    Open,
    Recovering,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentReviewState {
    Unreviewed,
    Acknowledged,
    Investigated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentCause {
    ExitCode,
    Signal,
    CoreDump,
    Timeout,
    Watchdog,
    ResourceFailure,
    StartLimit,
    Unknown,
}

impl From<TerminationKind> for IncidentCause {
    fn from(value: TerminationKind) -> Self {
        match value {
            TerminationKind::ExitCode => Self::ExitCode,
            TerminationKind::Signal => Self::Signal,
            TerminationKind::CoreDump => Self::CoreDump,
            TerminationKind::Timeout => Self::Timeout,
            TerminationKind::Watchdog => Self::Watchdog,
            TerminationKind::ResourceFailure => Self::ResourceFailure,
            TerminationKind::StartLimit => Self::StartLimit,
            TerminationKind::Clean | TerminationKind::Unknown => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentConfidence {
    Confirmed,
    Inferred,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentEvidence {
    fact_id: IncidentFactId,
    unit_name: IncidentUnitName,
    occurred_at: DateTime<Utc>,
    process: ProcessState,
    invocation_id: Option<String>,
    restart_count: Option<u32>,
    termination: Option<TerminationEvidence>,
    cause: IncidentCause,
    confidence: IncidentConfidence,
}

impl IncidentEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fact_id: IncidentFactId,
        unit_name: IncidentUnitName,
        occurred_at: DateTime<Utc>,
        process: ProcessState,
        invocation_id: Option<String>,
        restart_count: Option<u32>,
        termination: Option<TerminationEvidence>,
        confidence: IncidentConfidence,
    ) -> Result<Self, InvalidIncident> {
        if process == ProcessState::Unknown
            || invocation_id
                .as_ref()
                .is_some_and(|value| value.trim().is_empty())
        {
            return Err(InvalidIncident::Evidence);
        }
        let cause = termination
            .as_ref()
            .map_or(IncidentCause::Unknown, |value| value.kind().into());
        Ok(Self {
            fact_id,
            unit_name,
            occurred_at,
            process,
            invocation_id,
            restart_count,
            termination,
            cause,
            confidence,
        })
    }

    pub const fn fact_id(&self) -> &IncidentFactId {
        &self.fact_id
    }

    pub const fn unit_name(&self) -> &IncidentUnitName {
        &self.unit_name
    }

    pub const fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }

    pub const fn process(&self) -> ProcessState {
        self.process
    }

    pub fn invocation_id(&self) -> Option<&str> {
        self.invocation_id.as_deref()
    }

    pub const fn restart_count(&self) -> Option<u32> {
        self.restart_count
    }

    pub const fn termination(&self) -> Option<&TerminationEvidence> {
        self.termination.as_ref()
    }

    pub const fn cause(&self) -> IncidentCause {
        self.cause
    }

    pub const fn confidence(&self) -> IncidentConfidence {
        self.confidence
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IncidentReviewerId(i64);

impl IncidentReviewerId {
    pub fn new(value: i64) -> Result<Self, InvalidIncident> {
        (value > 0)
            .then_some(Self(value))
            .ok_or(InvalidIncident::Reviewer)
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentReviewEntry {
    reviewer_id: IncidentReviewerId,
    state: IncidentReviewState,
    note: String,
    at: DateTime<Utc>,
}

impl IncidentReviewEntry {
    pub const fn reviewer_id(&self) -> IncidentReviewerId {
        self.reviewer_id
    }

    pub const fn state(&self) -> IncidentReviewState {
        self.state
    }

    pub fn note(&self) -> &str {
        &self.note
    }

    pub const fn at(&self) -> DateTime<Utc> {
        self.at
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentChange {
    Applied,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incident {
    id: IncidentId,
    instance_id: ServerInstanceId,
    kind: IncidentKind,
    cause: IncidentCause,
    confidence: IncidentConfidence,
    operational_state: IncidentOperationalState,
    review_state: IncidentReviewState,
    opened_at: DateTime<Utc>,
    recovered_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
    version: u64,
    evidence: Vec<IncidentEvidence>,
    related_operation_ids: Vec<LifecycleOperationId>,
    review_history: Vec<IncidentReviewEntry>,
}

impl Incident {
    pub fn open(
        id: IncidentId,
        instance_id: ServerInstanceId,
        kind: IncidentKind,
        opening: IncidentEvidence,
    ) -> Result<Self, InvalidIncident> {
        let valid_process = match kind {
            IncidentKind::Outage => {
                opening.process == ProcessState::Failed
                    || (opening.process == ProcessState::Inactive
                        && opening.cause != IncidentCause::Unknown)
            }
            IncidentKind::UnplannedStop => opening.process == ProcessState::Inactive,
            IncidentKind::UnexpectedRestart => opening.process == ProcessState::Active,
        };
        if !valid_process {
            return Err(InvalidIncident::Evidence);
        }
        let opened_at = opening.occurred_at;
        let resolved = kind == IncidentKind::UnexpectedRestart;
        Ok(Self {
            id,
            instance_id,
            kind,
            cause: opening.cause,
            confidence: opening.confidence,
            operational_state: if resolved {
                IncidentOperationalState::Resolved
            } else {
                IncidentOperationalState::Open
            },
            review_state: IncidentReviewState::Unreviewed,
            opened_at,
            recovered_at: resolved.then_some(opened_at),
            updated_at: opened_at,
            version: 0,
            evidence: vec![opening],
            related_operation_ids: Vec::new(),
            review_history: Vec::new(),
        })
    }

    pub fn begin_recovery(
        &mut self,
        evidence: IncidentEvidence,
        at: DateTime<Utc>,
    ) -> Result<IncidentChange, InvalidIncident> {
        if let Some(duplicate) = self.duplicate(&evidence)? {
            return Ok(duplicate);
        }
        if self.operational_state != IncidentOperationalState::Open
            || evidence.process != ProcessState::Activating
        {
            return Err(InvalidIncident::Transition);
        }
        self.append_evidence(evidence, at)?;
        self.operational_state = IncidentOperationalState::Recovering;
        Ok(IncidentChange::Applied)
    }

    pub fn resolve(
        &mut self,
        evidence: IncidentEvidence,
        at: DateTime<Utc>,
    ) -> Result<IncidentChange, InvalidIncident> {
        if let Some(duplicate) = self.duplicate(&evidence)? {
            return Ok(duplicate);
        }
        if self.operational_state == IncidentOperationalState::Resolved
            || evidence.process != ProcessState::Active
            || evidence.occurred_at < self.opened_at
        {
            return Err(InvalidIncident::Transition);
        }
        let recovered_at = evidence.occurred_at;
        self.append_evidence(evidence, at)?;
        self.operational_state = IncidentOperationalState::Resolved;
        self.recovered_at = Some(recovered_at);
        Ok(IncidentChange::Applied)
    }

    pub fn acknowledge(
        &mut self,
        reviewer_id: IncidentReviewerId,
        note: impl Into<String>,
        at: DateTime<Utc>,
    ) -> Result<(), InvalidIncident> {
        self.review(
            IncidentReviewState::Unreviewed,
            IncidentReviewState::Acknowledged,
            reviewer_id,
            note.into(),
            at,
        )
    }

    pub fn investigate(
        &mut self,
        reviewer_id: IncidentReviewerId,
        note: impl Into<String>,
        at: DateTime<Utc>,
    ) -> Result<(), InvalidIncident> {
        self.review(
            IncidentReviewState::Acknowledged,
            IncidentReviewState::Investigated,
            reviewer_id,
            note.into(),
            at,
        )
    }

    pub fn link_operation(
        &mut self,
        operation_id: LifecycleOperationId,
        at: DateTime<Utc>,
    ) -> Result<IncidentChange, InvalidIncident> {
        if self.related_operation_ids.contains(&operation_id) {
            return Ok(IncidentChange::Duplicate);
        }
        self.advance(at)?;
        self.related_operation_ids.push(operation_id);
        Ok(IncidentChange::Applied)
    }

    fn duplicate(
        &self,
        evidence: &IncidentEvidence,
    ) -> Result<Option<IncidentChange>, InvalidIncident> {
        match self
            .evidence
            .iter()
            .find(|known| known.fact_id == evidence.fact_id)
        {
            Some(known) if known == evidence => Ok(Some(IncidentChange::Duplicate)),
            Some(_) => Err(InvalidIncident::ConflictingFact),
            None => Ok(None),
        }
    }

    fn append_evidence(
        &mut self,
        evidence: IncidentEvidence,
        at: DateTime<Utc>,
    ) -> Result<(), InvalidIncident> {
        if evidence.occurred_at < self.opened_at {
            return Err(InvalidIncident::Timeline);
        }
        if evidence.unit_name != self.evidence[0].unit_name {
            return Err(InvalidIncident::Evidence);
        }
        self.advance(at)?;
        self.evidence.push(evidence);
        Ok(())
    }

    fn review(
        &mut self,
        expected: IncidentReviewState,
        next: IncidentReviewState,
        reviewer_id: IncidentReviewerId,
        note: String,
        at: DateTime<Utc>,
    ) -> Result<(), InvalidIncident> {
        if self.review_state != expected {
            return Err(InvalidIncident::Transition);
        }
        if note.trim().is_empty() || note.len() > MAX_REVIEW_NOTE_BYTES {
            return Err(InvalidIncident::ReviewNote);
        }
        self.advance(at)?;
        self.review_state = next;
        self.review_history.push(IncidentReviewEntry {
            reviewer_id,
            state: next,
            note,
            at,
        });
        Ok(())
    }

    fn advance(&mut self, at: DateTime<Utc>) -> Result<(), InvalidIncident> {
        if at < self.updated_at {
            return Err(InvalidIncident::Timeline);
        }
        let next = self
            .version
            .checked_add(1)
            .ok_or(InvalidIncident::VersionOverflow)?;
        self.updated_at = at;
        self.version = next;
        Ok(())
    }

    pub const fn id(&self) -> IncidentId {
        self.id
    }
    pub const fn instance_id(&self) -> &ServerInstanceId {
        &self.instance_id
    }
    pub const fn kind(&self) -> IncidentKind {
        self.kind
    }
    pub const fn cause(&self) -> IncidentCause {
        self.cause
    }
    pub const fn confidence(&self) -> IncidentConfidence {
        self.confidence
    }
    pub const fn operational_state(&self) -> IncidentOperationalState {
        self.operational_state
    }
    pub const fn review_state(&self) -> IncidentReviewState {
        self.review_state
    }
    pub const fn opened_at(&self) -> DateTime<Utc> {
        self.opened_at
    }
    pub const fn recovered_at(&self) -> Option<DateTime<Utc>> {
        self.recovered_at
    }
    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    pub const fn version(&self) -> u64 {
        self.version
    }
    pub fn evidence(&self) -> &[IncidentEvidence] {
        &self.evidence
    }

    pub fn unit_name(&self) -> &IncidentUnitName {
        self.evidence[0].unit_name()
    }
    pub fn related_operation_ids(&self) -> &[LifecycleOperationId] {
        &self.related_operation_ids
    }
    pub fn review_history(&self) -> &[IncidentReviewEntry] {
        &self.review_history
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidIncident {
    #[error("invalid incident systemd unit name")]
    UnitName,
    #[error("invalid incident fact identity")]
    FactId,
    #[error("invalid incident evidence")]
    Evidence,
    #[error("incident fact identity has conflicting evidence")]
    ConflictingFact,
    #[error("invalid incident transition")]
    Transition,
    #[error("incident timeline is invalid")]
    Timeline,
    #[error("incident version overflow")]
    VersionOverflow,
    #[error("incident reviewer ID must be positive")]
    Reviewer,
    #[error("incident review note is invalid")]
    ReviewNote,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + seconds, 0).unwrap()
    }

    fn evidence(
        key: &str,
        seconds: i64,
        process: ProcessState,
        termination: Option<TerminationEvidence>,
    ) -> IncidentEvidence {
        IncidentEvidence::new(
            IncidentFactId::live(key).unwrap(),
            IncidentUnitName::new("lara-game@test.service").unwrap(),
            at(seconds),
            process,
            Some("invocation-a".into()),
            Some(1),
            termination,
            IncidentConfidence::Confirmed,
        )
        .unwrap()
    }

    fn outage() -> Incident {
        Incident::open(
            IncidentId::new(),
            ServerInstanceId::new("test").unwrap(),
            IncidentKind::Outage,
            evidence(
                "failure",
                0,
                ProcessState::Failed,
                Some(TerminationEvidence::new(TerminationKind::ExitCode, Some(1))),
            ),
        )
        .unwrap()
    }

    #[test]
    fn automatic_recovery_preserves_unreviewed_status_until_operator_reviews() {
        let mut incident = outage();
        let reviewer = IncidentReviewerId::new(42).unwrap();

        assert_eq!(incident.cause(), IncidentCause::ExitCode);
        assert_eq!(incident.operational_state(), IncidentOperationalState::Open);
        assert_eq!(incident.version(), 0);
        assert_eq!(
            incident
                .begin_recovery(
                    evidence("starting", 5, ProcessState::Activating, None),
                    at(5)
                )
                .unwrap(),
            IncidentChange::Applied
        );
        assert_eq!(
            incident
                .resolve(evidence("ready", 9, ProcessState::Active, None), at(9))
                .unwrap(),
            IncidentChange::Applied
        );

        assert_eq!(
            incident.operational_state(),
            IncidentOperationalState::Resolved
        );
        assert_eq!(incident.recovered_at(), Some(at(9)));
        assert_eq!(incident.review_state(), IncidentReviewState::Unreviewed);
        assert_eq!(incident.evidence().len(), 3);
        assert_eq!(incident.version(), 2);

        incident
            .acknowledge(reviewer, "Seen by on-call", at(12))
            .unwrap();
        incident
            .investigate(reviewer, "Checked journal", at(20))
            .unwrap();
        assert_eq!(incident.review_state(), IncidentReviewState::Investigated);
        assert_eq!(incident.review_history().len(), 2);
        assert_eq!(incident.review_history()[0].reviewer_id(), reviewer);
        assert_eq!(incident.version(), 4);
    }

    #[test]
    fn replaying_same_fact_is_idempotent_but_conflicting_fact_is_rejected() {
        let mut incident = outage();
        let ready = evidence("ready", 9, ProcessState::Active, None);
        incident.resolve(ready.clone(), at(9)).unwrap();
        let original = incident.clone();

        assert_eq!(
            incident.resolve(ready, at(20)).unwrap(),
            IncidentChange::Duplicate
        );
        assert_eq!(incident, original);
        let conflicting = evidence("ready", 10, ProcessState::Active, None);
        assert_eq!(
            incident.resolve(conflicting, at(20)),
            Err(InvalidIncident::ConflictingFact)
        );
        assert_eq!(incident, original);
    }

    #[test]
    fn invalid_transitions_and_old_processing_time_do_not_mutate_incident() {
        let mut incident = outage();
        let original = incident.clone();

        assert_eq!(
            incident.begin_recovery(evidence("wrong", 3, ProcessState::Active, None), at(3)),
            Err(InvalidIncident::Transition)
        );
        assert_eq!(
            incident.resolve(evidence("ready", 3, ProcessState::Active, None), at(-1)),
            Err(InvalidIncident::Timeline)
        );
        assert_eq!(incident, original);
        incident
            .resolve(evidence("ready", 3, ProcessState::Active, None), at(3))
            .unwrap();
        assert_eq!(
            incident.resolve(evidence("another", 10, ProcessState::Active, None), at(10)),
            Err(InvalidIncident::Transition)
        );
    }

    #[test]
    fn instantaneous_unexpected_restart_is_resolved_but_requires_review() {
        let incident = Incident::open(
            IncidentId::new(),
            ServerInstanceId::new("test").unwrap(),
            IncidentKind::UnexpectedRestart,
            evidence("new-invocation", 0, ProcessState::Active, None),
        )
        .unwrap();

        assert_eq!(
            incident.operational_state(),
            IncidentOperationalState::Resolved
        );
        assert_eq!(incident.recovered_at(), Some(incident.opened_at()));
        assert_eq!(incident.review_state(), IncidentReviewState::Unreviewed);
        assert_eq!(incident.cause(), IncidentCause::Unknown);
    }

    #[test]
    fn facts_and_reviewers_have_validated_identity() {
        assert_eq!(IncidentFactId::live(" "), Err(InvalidIncident::FactId));
        assert_eq!(
            IncidentUnitName::new("lara-game@test"),
            Err(InvalidIncident::UnitName)
        );
        assert_eq!(
            IncidentFactId::journal(Uuid::nil(), "bad\nheader"),
            Err(InvalidIncident::FactId)
        );
        assert_eq!(IncidentReviewerId::new(0), Err(InvalidIncident::Reviewer));
        assert_eq!(
            IncidentEvidence::new(
                IncidentFactId::live("fact").unwrap(),
                IncidentUnitName::new("lara-game@test.service").unwrap(),
                at(0),
                ProcessState::Unknown,
                None,
                None,
                None,
                IncidentConfidence::Unknown,
            ),
            Err(InvalidIncident::Evidence)
        );
    }

    #[test]
    fn review_history_and_operation_links_are_auditable() {
        let mut incident = outage();
        let reviewer = IncidentReviewerId::new(7).unwrap();
        let operation = LifecycleOperationId::new();

        assert_eq!(
            incident.link_operation(operation, at(1)).unwrap(),
            IncidentChange::Applied
        );
        assert_eq!(
            incident.link_operation(operation, at(2)).unwrap(),
            IncidentChange::Duplicate
        );
        assert_eq!(incident.related_operation_ids(), &[operation]);
        assert_eq!(
            incident.investigate(reviewer, "Premature", at(2)),
            Err(InvalidIncident::Transition)
        );
        assert_eq!(
            incident.acknowledge(reviewer, "   ", at(2)),
            Err(InvalidIncident::ReviewNote)
        );
        incident
            .acknowledge(reviewer, "Investigating", at(2))
            .unwrap();
        assert_eq!(incident.review_history()[0].note(), "Investigating");
        assert_eq!(incident.review_history()[0].at(), at(2));
        assert_eq!(
            incident.acknowledge(reviewer, "Again", at(3)),
            Err(InvalidIncident::Transition)
        );
        assert_eq!(incident.version(), 2);
    }

    #[test]
    fn inactive_abnormal_exit_is_outage_and_late_recovery_is_rejected() {
        let mut incident = Incident::open(
            IncidentId::new(),
            ServerInstanceId::new("test").unwrap(),
            IncidentKind::Outage,
            evidence(
                "exit",
                10,
                ProcessState::Inactive,
                Some(TerminationEvidence::new(TerminationKind::Signal, Some(9))),
            ),
        )
        .unwrap();
        assert_eq!(incident.cause(), IncidentCause::Signal);
        assert_eq!(
            incident.resolve(
                evidence("old-active", 9, ProcessState::Active, None),
                at(11)
            ),
            Err(InvalidIncident::Transition)
        );
        assert_eq!(incident.version(), 0);
    }

    #[test]
    fn evidence_from_another_unit_cannot_be_attached_to_incident() {
        let mut incident = outage();
        let mut other = evidence("other-unit", 3, ProcessState::Active, None);
        other.unit_name = IncidentUnitName::new("lara-game@other.service").unwrap();

        assert_eq!(
            incident.resolve(other, at(3)),
            Err(InvalidIncident::Evidence)
        );
        assert_eq!(incident.unit_name().as_str(), "lara-game@test.service");
        assert_eq!(incident.version(), 0);
    }
}
