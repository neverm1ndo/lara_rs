use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use super::{ProcessState, ReadinessStatus, ServerInstanceId};

const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
const MAX_ACTOR_NAME_BYTES: usize = 100;
const MAX_JOB_REFERENCE_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LifecycleOperationId(Uuid);

impl LifecycleOperationId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }
}

impl Default for LifecycleOperationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for LifecycleOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for LifecycleOperationId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LifecycleActorId(i64);

impl LifecycleActorId {
    pub fn new(value: i64) -> Result<Self, InvalidLifecycleOperation> {
        (value > 0)
            .then_some(Self(value))
            .ok_or(InvalidLifecycleOperation::ActorId)
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidLifecycleOperation> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_IDEMPOTENCY_KEY_BYTES
            && value.bytes().all(|byte| byte.is_ascii_graphic());
        valid
            .then_some(Self(value))
            .ok_or(InvalidLifecycleOperation::IdempotencyKey)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestFingerprint(String);

impl RequestFingerprint {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidLifecycleOperation> {
        let value = value.into();
        let valid = value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        valid
            .then_some(Self(value))
            .ok_or(InvalidLifecycleOperation::RequestFingerprint)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdJobReference(String);

impl SystemdJobReference {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidLifecycleOperation> {
        let value = value.into();
        let valid = value.len() > 1
            && value.len() <= MAX_JOB_REFERENCE_BYTES
            && value.starts_with('/')
            && value.split('/').skip(1).all(|segment| {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            });
        valid
            .then_some(Self(value))
            .ok_or(InvalidLifecycleOperation::SystemdJobReference)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleAction {
    Start,
    Stop,
    Restart,
}

impl LifecycleAction {
    pub const fn expected_state(self) -> LifecycleExpectedState {
        match self {
            Self::Start | Self::Restart => LifecycleExpectedState::Active,
            Self::Stop => LifecycleExpectedState::Inactive,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleExpectedState {
    Active,
    Inactive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleFailureCode {
    RuntimeUnavailable,
    RuntimeRejected,
    ObservationUnavailable,
    UnexpectedFinalState,
    ReconciliationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleOperationEvidence {
    process: ProcessState,
    readiness: ReadinessStatus,
    observed_at: Option<DateTime<Utc>>,
    restart_count: Option<u32>,
    invocation_id: Option<String>,
}

impl LifecycleOperationEvidence {
    pub fn new(
        process: ProcessState,
        readiness: ReadinessStatus,
        observed_at: Option<DateTime<Utc>>,
        restart_count: Option<u32>,
        invocation_id: Option<String>,
    ) -> Self {
        Self {
            process,
            readiness,
            observed_at,
            restart_count,
            invocation_id: invocation_id.filter(|value| !value.trim().is_empty()),
        }
    }

    pub const fn process(&self) -> ProcessState {
        self.process
    }

    pub const fn readiness(&self) -> ReadinessStatus {
        self.readiness
    }

    pub const fn observed_at(&self) -> Option<DateTime<Utc>> {
        self.observed_at
    }

    pub const fn restart_count(&self) -> Option<u32> {
        self.restart_count
    }

    pub fn invocation_id(&self) -> Option<&str> {
        self.invocation_id.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleOperationState {
    Requested,
    Dispatching,
    WaitingForState { job: SystemdJobReference },
    Succeeded,
    Failed { code: LifecycleFailureCode },
    TimedOut,
}

impl LifecycleOperationState {
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed { .. } | Self::TimedOut)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LifecycleOperationVersion(u64);

impl LifecycleOperationVersion {
    pub const fn initial() -> Self {
        Self(0)
    }

    pub const fn from_value(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, InvalidLifecycleOperation> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(InvalidLifecycleOperation::VersionOverflow)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleOperation {
    id: LifecycleOperationId,
    instance_id: ServerInstanceId,
    action: LifecycleAction,
    actor_id: LifecycleActorId,
    actor_display_name: String,
    idempotency_key: IdempotencyKey,
    request_fingerprint: RequestFingerprint,
    expected_state: LifecycleExpectedState,
    initial_evidence: LifecycleOperationEvidence,
    final_evidence: Option<LifecycleOperationEvidence>,
    state: LifecycleOperationState,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    deadline: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    version: LifecycleOperationVersion,
}

impl LifecycleOperation {
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        id: LifecycleOperationId,
        instance_id: ServerInstanceId,
        action: LifecycleAction,
        actor_id: LifecycleActorId,
        actor_display_name: impl Into<String>,
        idempotency_key: IdempotencyKey,
        request_fingerprint: RequestFingerprint,
        initial_evidence: LifecycleOperationEvidence,
        created_at: DateTime<Utc>,
        deadline: DateTime<Utc>,
    ) -> Result<Self, InvalidLifecycleOperation> {
        let actor_display_name = validate_actor_name(actor_display_name.into())?;
        if deadline <= created_at {
            return Err(InvalidLifecycleOperation::Deadline);
        }
        Ok(Self {
            id,
            instance_id,
            action,
            actor_id,
            actor_display_name,
            idempotency_key,
            request_fingerprint,
            expected_state: action.expected_state(),
            initial_evidence,
            final_evidence: None,
            state: LifecycleOperationState::Requested,
            created_at,
            updated_at: created_at,
            deadline,
            completed_at: None,
            version: LifecycleOperationVersion::initial(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rehydrate(
        id: LifecycleOperationId,
        instance_id: ServerInstanceId,
        action: LifecycleAction,
        actor_id: LifecycleActorId,
        actor_display_name: String,
        idempotency_key: IdempotencyKey,
        request_fingerprint: RequestFingerprint,
        expected_state: LifecycleExpectedState,
        initial_evidence: LifecycleOperationEvidence,
        final_evidence: Option<LifecycleOperationEvidence>,
        state: LifecycleOperationState,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        deadline: DateTime<Utc>,
        completed_at: Option<DateTime<Utc>>,
        version: LifecycleOperationVersion,
    ) -> Result<Self, InvalidLifecycleOperation> {
        let actor_display_name = validate_actor_name(actor_display_name)?;
        if expected_state != action.expected_state() {
            return Err(InvalidLifecycleOperation::ExpectedState);
        }
        if deadline <= created_at || updated_at < created_at {
            return Err(InvalidLifecycleOperation::Timeline);
        }
        match (&state, completed_at, final_evidence.as_ref()) {
            (LifecycleOperationState::Succeeded, Some(completed), Some(_))
            | (LifecycleOperationState::Failed { .. }, Some(completed), _)
            | (LifecycleOperationState::TimedOut, Some(completed), _)
                if completed == updated_at => {}
            (state, None, None) if !state.is_terminal() => {}
            _ => return Err(InvalidLifecycleOperation::StateEvidence),
        }
        Ok(Self {
            id,
            instance_id,
            action,
            actor_id,
            actor_display_name,
            idempotency_key,
            request_fingerprint,
            expected_state,
            initial_evidence,
            final_evidence,
            state,
            created_at,
            updated_at,
            deadline,
            completed_at,
            version,
        })
    }

    pub fn begin_dispatch(&mut self, at: DateTime<Utc>) -> Result<(), InvalidLifecycleOperation> {
        self.transition(LifecycleOperationState::Requested, at, |operation| {
            operation.state = LifecycleOperationState::Dispatching;
        })
    }

    pub fn wait_for_state(
        &mut self,
        job: SystemdJobReference,
        at: DateTime<Utc>,
    ) -> Result<(), InvalidLifecycleOperation> {
        self.transition(LifecycleOperationState::Dispatching, at, move |operation| {
            operation.state = LifecycleOperationState::WaitingForState { job };
        })
    }

    pub fn succeed(
        &mut self,
        evidence: LifecycleOperationEvidence,
        at: DateTime<Utc>,
    ) -> Result<(), InvalidLifecycleOperation> {
        self.finish_from_waiting(at, move |operation| {
            operation.state = LifecycleOperationState::Succeeded;
            operation.final_evidence = Some(evidence);
        })
    }

    pub fn fail(
        &mut self,
        code: LifecycleFailureCode,
        evidence: Option<LifecycleOperationEvidence>,
        at: DateTime<Utc>,
    ) -> Result<(), InvalidLifecycleOperation> {
        if !matches!(
            self.state,
            LifecycleOperationState::Dispatching | LifecycleOperationState::WaitingForState { .. }
        ) {
            return Err(InvalidLifecycleOperation::Transition);
        }
        self.advance_time(at)?;
        self.state = LifecycleOperationState::Failed { code };
        self.final_evidence = evidence;
        self.completed_at = Some(at);
        self.version = self.version.next()?;
        Ok(())
    }

    pub fn time_out(
        &mut self,
        evidence: Option<LifecycleOperationEvidence>,
        at: DateTime<Utc>,
    ) -> Result<(), InvalidLifecycleOperation> {
        if self.state.is_terminal() || at < self.deadline {
            return Err(InvalidLifecycleOperation::Transition);
        }
        self.advance_time(at)?;
        self.state = LifecycleOperationState::TimedOut;
        self.final_evidence = evidence;
        self.completed_at = Some(at);
        self.version = self.version.next()?;
        Ok(())
    }

    fn transition(
        &mut self,
        required: LifecycleOperationState,
        at: DateTime<Utc>,
        change: impl FnOnce(&mut Self),
    ) -> Result<(), InvalidLifecycleOperation> {
        if self.state != required {
            return Err(InvalidLifecycleOperation::Transition);
        }
        self.advance_time(at)?;
        change(self);
        self.version = self.version.next()?;
        Ok(())
    }

    fn finish_from_waiting(
        &mut self,
        at: DateTime<Utc>,
        change: impl FnOnce(&mut Self),
    ) -> Result<(), InvalidLifecycleOperation> {
        if !matches!(self.state, LifecycleOperationState::WaitingForState { .. }) {
            return Err(InvalidLifecycleOperation::Transition);
        }
        self.advance_time(at)?;
        change(self);
        self.completed_at = Some(at);
        self.version = self.version.next()?;
        Ok(())
    }

    fn advance_time(&mut self, at: DateTime<Utc>) -> Result<(), InvalidLifecycleOperation> {
        if at < self.updated_at {
            return Err(InvalidLifecycleOperation::Timeline);
        }
        self.updated_at = at;
        Ok(())
    }

    pub const fn id(&self) -> LifecycleOperationId {
        self.id
    }
    pub const fn instance_id(&self) -> &ServerInstanceId {
        &self.instance_id
    }
    pub const fn action(&self) -> LifecycleAction {
        self.action
    }
    pub const fn actor_id(&self) -> LifecycleActorId {
        self.actor_id
    }
    pub fn actor_display_name(&self) -> &str {
        &self.actor_display_name
    }
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
    pub const fn request_fingerprint(&self) -> &RequestFingerprint {
        &self.request_fingerprint
    }
    pub const fn expected_state(&self) -> LifecycleExpectedState {
        self.expected_state
    }
    pub const fn initial_evidence(&self) -> &LifecycleOperationEvidence {
        &self.initial_evidence
    }
    pub const fn final_evidence(&self) -> Option<&LifecycleOperationEvidence> {
        self.final_evidence.as_ref()
    }
    pub const fn state(&self) -> &LifecycleOperationState {
        &self.state
    }
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    pub const fn deadline(&self) -> DateTime<Utc> {
        self.deadline
    }
    pub const fn completed_at(&self) -> Option<DateTime<Utc>> {
        self.completed_at
    }
    pub const fn version(&self) -> LifecycleOperationVersion {
        self.version
    }
}

fn validate_actor_name(value: String) -> Result<String, InvalidLifecycleOperation> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_ACTOR_NAME_BYTES
        || trimmed.chars().any(char::is_control)
    {
        return Err(InvalidLifecycleOperation::ActorDisplayName);
    }
    Ok(trimmed.to_owned())
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidLifecycleOperation {
    #[error("lifecycle actor ID must be positive")]
    ActorId,
    #[error("actor display name must contain between 1 and 100 safe bytes")]
    ActorDisplayName,
    #[error("idempotency key must contain between 1 and 128 visible ASCII bytes")]
    IdempotencyKey,
    #[error("request fingerprint must be a lowercase SHA-256 hexadecimal digest")]
    RequestFingerprint,
    #[error("systemd job reference must be a bounded D-Bus object path")]
    SystemdJobReference,
    #[error("operation deadline must be later than creation time")]
    Deadline,
    #[error("persisted expected state does not match the lifecycle action")]
    ExpectedState,
    #[error("operation timestamps are inconsistent")]
    Timeline,
    #[error("operation state and evidence are inconsistent")]
    StateEvidence,
    #[error("lifecycle operation state transition is not permitted")]
    Transition,
    #[error("lifecycle operation version overflow")]
    VersionOverflow,
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn evidence(process: ProcessState) -> LifecycleOperationEvidence {
        LifecycleOperationEvidence::new(
            process,
            ReadinessStatus::Ready,
            DateTime::from_timestamp(1_700_000_000, 0),
            Some(2),
            Some("invocation-1".into()),
        )
    }

    fn operation() -> LifecycleOperation {
        let created_at = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        LifecycleOperation::request(
            LifecycleOperationId::new(),
            ServerInstanceId::new("test").unwrap(),
            LifecycleAction::Restart,
            LifecycleActorId::new(42).unwrap(),
            " Developer ",
            IdempotencyKey::new("request-1").unwrap(),
            RequestFingerprint::new("a".repeat(64)).unwrap(),
            evidence(ProcessState::Active),
            created_at,
            created_at + Duration::seconds(30),
        )
        .unwrap()
    }

    #[test]
    fn advances_through_the_durable_happy_path() {
        let mut operation = operation();
        let created_at = operation.created_at();
        operation.begin_dispatch(created_at).unwrap();
        operation
            .wait_for_state(
                SystemdJobReference::new("/org/freedesktop/systemd1/job/7").unwrap(),
                created_at + Duration::seconds(1),
            )
            .unwrap();
        operation
            .succeed(
                evidence(ProcessState::Active),
                created_at + Duration::seconds(2),
            )
            .unwrap();

        assert_eq!(operation.state(), &LifecycleOperationState::Succeeded);
        assert_eq!(operation.version().get(), 3);
        assert!(operation.completed_at().is_some());
        assert!(operation.final_evidence().is_some());
    }

    #[test]
    fn rejects_skipped_and_backdated_transitions() {
        let mut operation = operation();
        let created_at = operation.created_at();
        assert_eq!(
            operation.succeed(evidence(ProcessState::Active), created_at),
            Err(InvalidLifecycleOperation::Transition)
        );
        operation.begin_dispatch(created_at).unwrap();
        assert_eq!(
            operation.wait_for_state(
                SystemdJobReference::new("/job/1").unwrap(),
                created_at - Duration::seconds(1),
            ),
            Err(InvalidLifecycleOperation::Timeline)
        );
    }

    #[test]
    fn timeout_requires_the_deadline_and_terminal_states_are_final() {
        let mut operation = operation();
        let before_deadline = operation.deadline() - Duration::seconds(1);
        assert_eq!(
            operation.time_out(None, before_deadline),
            Err(InvalidLifecycleOperation::Transition)
        );
        operation.time_out(None, operation.deadline()).unwrap();
        assert_eq!(
            operation.fail(
                LifecycleFailureCode::ReconciliationFailed,
                None,
                operation.deadline()
            ),
            Err(InvalidLifecycleOperation::Transition)
        );
    }

    #[test]
    fn validates_external_correlation_values() {
        assert!(IdempotencyKey::new("contains space").is_err());
        assert!(IdempotencyKey::new("x".repeat(129)).is_err());
        assert!(RequestFingerprint::new("A".repeat(64)).is_err());
        assert!(SystemdJobReference::new("org/systemd/job/1").is_err());
        assert!(SystemdJobReference::new("/org/systemd/job/not-valid").is_err());
    }
}
