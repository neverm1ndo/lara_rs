use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::server_instances::domain::{
    InstanceReadiness, InstanceRuntimeState, LifecycleAction, LifecycleActorId,
    LifecycleFailureCode, LifecycleOperation, LifecycleOperationId, LifecycleOperationState,
    LifecycleOperationVersion, ServerInstanceId,
};

pub const OPERATION_UPDATED_EVENT: &str = "server_instance.operation.updated";
pub const STATE_CHANGED_EVENT: &str = "server_instance.state.changed";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerInstanceEvent {
    OperationUpdated(LifecycleOperationUpdatedEvent),
    StateChanged(ServerInstanceStateChangedEvent),
}

impl ServerInstanceEvent {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::OperationUpdated(_) => OPERATION_UPDATED_EVENT,
            Self::StateChanged(_) => STATE_CHANGED_EVENT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleOperationUpdatedEvent {
    event_id: String,
    sequence: LifecycleOperationVersion,
    occurred_at: DateTime<Utc>,
    instance_id: ServerInstanceId,
    operation_id: LifecycleOperationId,
    action: LifecycleAction,
    actor_id: LifecycleActorId,
    actor_display_name: String,
    state: LifecycleOperationState,
    deadline: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

impl LifecycleOperationUpdatedEvent {
    pub fn from_operation(operation: &LifecycleOperation) -> Self {
        let sequence = operation.version();
        Self {
            event_id: format!("lifecycle-operation:{}:{}", operation.id(), sequence.get()),
            sequence,
            occurred_at: operation.updated_at(),
            instance_id: operation.instance_id().clone(),
            operation_id: operation.id(),
            action: operation.action(),
            actor_id: operation.actor_id(),
            actor_display_name: operation.actor_display_name().to_owned(),
            state: operation.state().clone(),
            deadline: operation.deadline(),
            completed_at: operation.completed_at(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rehydrate(
        event_id: String,
        sequence: LifecycleOperationVersion,
        occurred_at: DateTime<Utc>,
        instance_id: ServerInstanceId,
        operation_id: LifecycleOperationId,
        action: LifecycleAction,
        actor_id: LifecycleActorId,
        actor_display_name: String,
        state: LifecycleOperationState,
        deadline: DateTime<Utc>,
        completed_at: Option<DateTime<Utc>>,
    ) -> Result<Self, InvalidLifecycleEvent> {
        let expected_id = format!("lifecycle-operation:{operation_id}:{}", sequence.get());
        if event_id != expected_id
            || actor_display_name.trim().is_empty()
            || state.is_terminal() != completed_at.is_some()
        {
            return Err(InvalidLifecycleEvent);
        }
        Ok(Self {
            event_id,
            sequence,
            occurred_at,
            instance_id,
            operation_id,
            action,
            actor_id,
            actor_display_name,
            state,
            deadline,
            completed_at,
        })
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }
    pub const fn sequence(&self) -> LifecycleOperationVersion {
        self.sequence
    }
    pub const fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    pub const fn instance_id(&self) -> &ServerInstanceId {
        &self.instance_id
    }
    pub const fn operation_id(&self) -> LifecycleOperationId {
        self.operation_id
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
    pub const fn state(&self) -> &LifecycleOperationState {
        &self.state
    }
    pub const fn deadline(&self) -> DateTime<Utc> {
        self.deadline
    }
    pub const fn completed_at(&self) -> Option<DateTime<Utc>> {
        self.completed_at
    }
    pub const fn failure_code(&self) -> Option<LifecycleFailureCode> {
        match self.state {
            LifecycleOperationState::Failed { code } => Some(code),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInstanceStateChangedEvent {
    event_id: String,
    sequence: i64,
    readiness_mode: InstanceReadiness,
    state: InstanceRuntimeState,
}

impl ServerInstanceStateChangedEvent {
    pub fn new(
        state: InstanceRuntimeState,
        readiness_mode: InstanceReadiness,
        emitted_at: DateTime<Utc>,
    ) -> Self {
        let sequence = emitted_at.timestamp_micros();
        Self {
            event_id: format!("runtime-state:{}:{sequence}", state.instance_id()),
            sequence,
            readiness_mode,
            state,
        }
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }
    pub const fn sequence(&self) -> i64 {
        self.sequence
    }
    pub const fn state(&self) -> &InstanceRuntimeState {
        &self.state
    }
    pub const fn readiness_mode(&self) -> InstanceReadiness {
        self.readiness_mode
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedLifecycleEvent {
    pub event: LifecycleOperationUpdatedEvent,
    pub lease_token: String,
}

pub type LifecycleEventOutboxFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, LifecycleEventOutboxError>> + Send + 'a>>;

pub trait LifecycleEventOutbox: Send + Sync {
    fn claim_next<'a>(
        &'a self,
        now: DateTime<Utc>,
        lease_until: DateTime<Utc>,
        lease_token: &'a str,
    ) -> LifecycleEventOutboxFuture<'a, Option<ClaimedLifecycleEvent>>;

    fn acknowledge<'a>(
        &'a self,
        claim: &'a ClaimedLifecycleEvent,
    ) -> LifecycleEventOutboxFuture<'a, ()>;
}

pub type LifecycleEventDeliveryFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), LifecycleEventDeliveryError>> + Send + 'a>>;

pub trait LifecycleEventDelivery: Send + Sync {
    fn deliver<'a>(&'a self, event: &'a ServerInstanceEvent) -> LifecycleEventDeliveryFuture<'a>;
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("lifecycle event outbox is unavailable: {message}")]
pub struct LifecycleEventOutboxError {
    pub message: String,
}

impl LifecycleEventOutboxError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("lifecycle event delivery failed: {message}")]
pub struct LifecycleEventDeliveryError {
    pub message: String,
}

impl LifecycleEventDeliveryError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("persisted lifecycle event is invalid")]
pub struct InvalidLifecycleEvent;

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;
    use crate::server_instances::domain::{
        IdempotencyKey, LifecycleOperationEvidence, ObservationStatus, ProcessState,
        ReadinessStatus, RequestFingerprint,
    };

    #[test]
    fn operation_event_id_and_sequence_are_stable() {
        let now = Utc::now();
        let operation = LifecycleOperation::request(
            LifecycleOperationId::new(),
            ServerInstanceId::new("dev-dm").unwrap(),
            LifecycleAction::Restart,
            LifecycleActorId::new(42).unwrap(),
            "neo",
            IdempotencyKey::new("request-1").unwrap(),
            RequestFingerprint::new("a".repeat(64)).unwrap(),
            LifecycleOperationEvidence::new(
                ProcessState::Active,
                ReadinessStatus::Ready,
                ObservationStatus::Observed,
                Some(now),
                Some(0),
                None,
            ),
            now,
            now + Duration::minutes(2),
        )
        .unwrap();

        let first = LifecycleOperationUpdatedEvent::from_operation(&operation);
        let second = LifecycleOperationUpdatedEvent::from_operation(&operation);

        assert_eq!(first, second);
        assert_eq!(first.sequence().get(), 0);
        assert_eq!(
            first.event_id(),
            format!("lifecycle-operation:{}:0", operation.id())
        );
    }
}
