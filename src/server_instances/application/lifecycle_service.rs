use std::{fmt::Write, sync::Arc, time::Duration};

use chrono::Duration as ChronoDuration;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    server_instances::{
        application::{
            lifecycle_operations::{
                LifecycleOperationClock, LifecycleOperationIdGenerator,
                LifecycleOperationListQuery, LifecycleOperationRepository,
                LifecycleOperationRepositoryError,
            },
            lifecycle_runtime::{LifecycleRuntime, LifecycleRuntimeError},
            registry::InstanceRegistry,
            runtime_state::{RuntimeStateReader, RuntimeStateRepositoryError},
        },
        domain::{
            IdempotencyKey, InstanceManagement, InstanceRuntimeState, LifecycleAction,
            LifecycleActorId, LifecycleFailureCode, LifecycleOperation, LifecycleOperationEvidence,
            LifecycleOperationId, LifecycleOperationState, ObservationStatus, ProcessState,
            ReadinessStatus, RequestFingerprint, ServerInstanceId,
        },
    },
    shared::user_role::UserRole,
};

pub struct LifecycleOperationService {
    registry: Arc<dyn InstanceRegistry>,
    operations: Arc<dyn LifecycleOperationRepository>,
    runtime: Arc<dyn LifecycleRuntime>,
    states: Arc<dyn RuntimeStateReader>,
    clock: Arc<dyn LifecycleOperationClock>,
    ids: Arc<dyn LifecycleOperationIdGenerator>,
    timeout: ChronoDuration,
}

impl LifecycleOperationService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: Arc<dyn InstanceRegistry>,
        operations: Arc<dyn LifecycleOperationRepository>,
        runtime: Arc<dyn LifecycleRuntime>,
        states: Arc<dyn RuntimeStateReader>,
        clock: Arc<dyn LifecycleOperationClock>,
        ids: Arc<dyn LifecycleOperationIdGenerator>,
        timeout: Duration,
    ) -> Result<Self, LifecycleOperationServiceError> {
        let timeout = ChronoDuration::from_std(timeout)
            .map_err(|_| LifecycleOperationServiceError::InvalidTimeout)?;
        if timeout.is_zero() {
            return Err(LifecycleOperationServiceError::InvalidTimeout);
        }
        Ok(Self {
            registry,
            operations,
            runtime,
            states,
            clock,
            ids,
            timeout,
        })
    }

    pub async fn request(
        &self,
        subject: &LifecycleSubject,
        command: LifecycleCommand,
    ) -> Result<LifecycleCommandResult, LifecycleOperationServiceError> {
        if !subject.is_developer() {
            return Err(LifecycleOperationServiceError::Forbidden);
        }
        let instance = self
            .registry
            .get(&command.instance_id)
            .ok_or(LifecycleOperationServiceError::InstanceNotFound)?;
        if instance.management() != InstanceManagement::Systemd {
            return Err(LifecycleOperationServiceError::InstanceNotManaged);
        }

        let fingerprint = request_fingerprint(&command.instance_id, command.action);
        if let Some(operation) = self
            .operations
            .find_by_idempotency_key(subject.actor_id, &command.idempotency_key)
            .await?
        {
            return self
                .resume_or_replay(
                    operation,
                    &fingerprint,
                    LifecycleCommandDisposition::Replayed,
                )
                .await;
        }

        let now = self.clock.now();
        let initial_evidence = self.read_evidence(&command.instance_id)?;
        let operation = LifecycleOperation::request(
            self.ids.next_id(),
            command.instance_id.clone(),
            command.action,
            subject.actor_id,
            subject.display_name.clone(),
            command.idempotency_key.clone(),
            fingerprint.clone(),
            initial_evidence,
            now,
            now + self.timeout,
        )?;

        match self.operations.insert(&operation).await {
            Ok(()) => {}
            Err(LifecycleOperationRepositoryError::AlreadyExists) => {
                return self
                    .resolve_insert_conflict(subject.actor_id, &command, &fingerprint)
                    .await;
            }
            Err(error) => return Err(error.into()),
        }

        self.resume_or_replay(
            operation,
            &fingerprint,
            LifecycleCommandDisposition::Created,
        )
        .await
    }

    pub async fn get(
        &self,
        subject: &LifecycleSubject,
        instance_id: &ServerInstanceId,
        operation_id: LifecycleOperationId,
    ) -> Result<LifecycleOperation, LifecycleOperationServiceError> {
        self.authorize_read(subject, instance_id)?;
        self.operations
            .find_by_id(operation_id)
            .await?
            .filter(|operation| operation.instance_id() == instance_id)
            .ok_or(LifecycleOperationServiceError::OperationNotFound)
    }

    pub async fn list(
        &self,
        subject: &LifecycleSubject,
        instance_id: &ServerInstanceId,
        query: LifecycleOperationListQuery,
    ) -> Result<Vec<LifecycleOperation>, LifecycleOperationServiceError> {
        self.authorize_read(subject, instance_id)?;
        self.operations
            .list_for_instance(instance_id, query)
            .await
            .map_err(Into::into)
    }

    pub async fn reconcile(
        &self,
        operation_id: LifecycleOperationId,
    ) -> Result<LifecycleReconciliationResult, LifecycleOperationServiceError> {
        let Some(mut operation) = self.operations.find_by_id(operation_id).await? else {
            return Err(LifecycleOperationServiceError::OperationNotFound);
        };
        if operation.state().is_terminal() {
            return Ok(LifecycleReconciliationResult {
                operation,
                changed: false,
            });
        }

        let now = self.clock.now();
        let evidence = self.read_evidence(operation.instance_id())?;
        let expected_version = operation.version();
        let changed = if now >= operation.deadline() {
            operation.time_out(Some(evidence), now)?;
            true
        } else if matches!(
            operation.state(),
            LifecycleOperationState::Dispatching | LifecycleOperationState::WaitingForState { .. }
        ) && completion_confirmed(&operation, &evidence)
        {
            if matches!(operation.state(), LifecycleOperationState::Dispatching) {
                operation.recover_succeeded_after_dispatch(evidence, now)?;
            } else {
                operation.succeed(evidence, now)?;
            }
            true
        } else {
            false
        };

        if changed {
            self.operations.save(&operation, expected_version).await?;
        }
        Ok(LifecycleReconciliationResult { operation, changed })
    }

    /// Recovers the single active operation for a trusted managed instance.
    /// `Requested` is safe to dispatch because the state was persisted before
    /// any runtime side effect. `Dispatching` is never dispatched again: it is
    /// completed only from observer evidence or by its deadline.
    pub async fn recover_active(
        &self,
        instance_id: &ServerInstanceId,
    ) -> Result<Option<LifecycleOperation>, LifecycleOperationServiceError> {
        let instance = self
            .registry
            .get(instance_id)
            .ok_or(LifecycleOperationServiceError::InstanceNotFound)?;
        if instance.management() != InstanceManagement::Systemd {
            return Err(LifecycleOperationServiceError::InstanceNotManaged);
        }
        let Some(operation) = self
            .operations
            .find_active_for_instance(instance_id)
            .await?
        else {
            return Ok(None);
        };
        if operation.state() == &LifecycleOperationState::Requested {
            let fingerprint = operation.request_fingerprint().clone();
            return self
                .resume_or_replay(
                    operation,
                    &fingerprint,
                    LifecycleCommandDisposition::Replayed,
                )
                .await
                .map(|result| Some(result.operation));
        }
        self.reconcile(operation.id())
            .await
            .map(|result| Some(result.operation))
    }

    async fn resolve_insert_conflict(
        &self,
        actor_id: LifecycleActorId,
        command: &LifecycleCommand,
        fingerprint: &RequestFingerprint,
    ) -> Result<LifecycleCommandResult, LifecycleOperationServiceError> {
        if let Some(operation) = self
            .operations
            .find_by_idempotency_key(actor_id, &command.idempotency_key)
            .await?
        {
            return self
                .resume_or_replay(
                    operation,
                    fingerprint,
                    LifecycleCommandDisposition::Replayed,
                )
                .await;
        }
        if let Some(operation) = self
            .operations
            .find_active_for_instance(&command.instance_id)
            .await?
        {
            return Err(LifecycleOperationServiceError::ActiveOperation {
                operation_id: operation.id(),
            });
        }
        Err(LifecycleOperationServiceError::ConcurrentRequest)
    }

    async fn resume_or_replay(
        &self,
        mut operation: LifecycleOperation,
        fingerprint: &RequestFingerprint,
        disposition: LifecycleCommandDisposition,
    ) -> Result<LifecycleCommandResult, LifecycleOperationServiceError> {
        ensure_matching_fingerprint(&operation, fingerprint)?;
        if operation.state() != &LifecycleOperationState::Requested {
            return Ok(LifecycleCommandResult {
                operation,
                disposition,
            });
        }

        let now = self.clock.now();
        if now >= operation.deadline() {
            let expected_version = operation.version();
            let evidence = self.read_evidence(operation.instance_id())?;
            operation.time_out(Some(evidence), now)?;
            self.operations.save(&operation, expected_version).await?;
            return Ok(LifecycleCommandResult {
                operation,
                disposition,
            });
        }

        let expected_version = operation.version();
        operation.begin_dispatch(now)?;
        match self.operations.save(&operation, expected_version).await {
            Ok(()) => {}
            Err(LifecycleOperationRepositoryError::ConcurrentModification) => {
                let operation = self
                    .operations
                    .find_by_id(operation.id())
                    .await?
                    .ok_or(LifecycleOperationServiceError::ConcurrentRequest)?;
                ensure_matching_fingerprint(&operation, fingerprint)?;
                return Ok(LifecycleCommandResult {
                    operation,
                    disposition: LifecycleCommandDisposition::Replayed,
                });
            }
            Err(error) => return Err(error.into()),
        }

        match self
            .runtime
            .dispatch(operation.instance_id(), operation.action())
            .await
        {
            Ok(job) => {
                let expected_version = operation.version();
                operation.wait_for_state(job, self.clock.now())?;
                self.operations.save(&operation, expected_version).await?;
            }
            Err(error) => {
                let expected_version = operation.version();
                operation.fail(runtime_failure_code(&error), None, self.clock.now())?;
                self.operations.save(&operation, expected_version).await?;
            }
        }

        Ok(LifecycleCommandResult {
            operation,
            disposition,
        })
    }

    fn read_evidence(
        &self,
        instance_id: &ServerInstanceId,
    ) -> Result<LifecycleOperationEvidence, LifecycleOperationServiceError> {
        let state = self
            .states
            .get(instance_id)?
            .unwrap_or_else(|| InstanceRuntimeState::not_observed(instance_id.clone()));
        Ok(LifecycleOperationEvidence::new(
            state.process(),
            state.readiness(),
            state.observation(),
            state.observed_at(),
            state.restart_count(),
            state.invocation_id().map(str::to_owned),
        ))
    }

    fn authorize_read(
        &self,
        subject: &LifecycleSubject,
        instance_id: &ServerInstanceId,
    ) -> Result<(), LifecycleOperationServiceError> {
        if !subject.is_developer() {
            return Err(LifecycleOperationServiceError::Forbidden);
        }
        self.registry
            .get(instance_id)
            .ok_or(LifecycleOperationServiceError::InstanceNotFound)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct LifecycleSubject {
    actor_id: LifecycleActorId,
    display_name: String,
    main_group: UserRole,
    permissions: Vec<UserRole>,
}

impl LifecycleSubject {
    pub fn new(
        actor_id: LifecycleActorId,
        display_name: impl Into<String>,
        main_group: UserRole,
        permissions: Vec<UserRole>,
    ) -> Self {
        Self {
            actor_id,
            display_name: display_name.into(),
            main_group,
            permissions,
        }
    }

    fn is_developer(&self) -> bool {
        self.main_group == UserRole::Developer || self.permissions.contains(&UserRole::Developer)
    }
}

#[derive(Debug, Clone)]
pub struct LifecycleCommand {
    pub instance_id: ServerInstanceId,
    pub action: LifecycleAction,
    pub idempotency_key: IdempotencyKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleCommandResult {
    pub operation: LifecycleOperation,
    pub disposition: LifecycleCommandDisposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleCommandDisposition {
    Created,
    Replayed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleReconciliationResult {
    pub operation: LifecycleOperation,
    pub changed: bool,
}

#[derive(Debug, Error)]
pub enum LifecycleOperationServiceError {
    #[error("developer role is required")]
    Forbidden,
    #[error("server instance does not exist")]
    InstanceNotFound,
    #[error("server instance is not managed by systemd")]
    InstanceNotManaged,
    #[error("idempotency key was already used for another request")]
    IdempotencyConflict { operation_id: LifecycleOperationId },
    #[error("another lifecycle operation is active for this instance")]
    ActiveOperation { operation_id: LifecycleOperationId },
    #[error("a concurrent request could not be resolved")]
    ConcurrentRequest,
    #[error("lifecycle operation does not exist")]
    OperationNotFound,
    #[error("lifecycle timeout must be positive and representable")]
    InvalidTimeout,
    #[error(transparent)]
    InvalidOperation(#[from] crate::server_instances::domain::InvalidLifecycleOperation),
    #[error(transparent)]
    Repository(#[from] LifecycleOperationRepositoryError),
    #[error("runtime state is unavailable")]
    RuntimeState(#[from] RuntimeStateRepositoryError),
}

fn ensure_matching_fingerprint(
    operation: &LifecycleOperation,
    fingerprint: &RequestFingerprint,
) -> Result<(), LifecycleOperationServiceError> {
    if operation.request_fingerprint() != fingerprint {
        return Err(LifecycleOperationServiceError::IdempotencyConflict {
            operation_id: operation.id(),
        });
    }
    Ok(())
}

fn request_fingerprint(
    instance_id: &ServerInstanceId,
    action: LifecycleAction,
) -> RequestFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(b"lara.lifecycle.v1\0");
    hasher.update(instance_id.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(match action {
        LifecycleAction::Start => b"start".as_slice(),
        LifecycleAction::Stop => b"stop".as_slice(),
        LifecycleAction::Restart => b"restart".as_slice(),
    });
    let mut encoded = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    RequestFingerprint::new(encoded).expect("SHA-256 is a valid request fingerprint")
}

fn runtime_failure_code(error: &LifecycleRuntimeError) -> LifecycleFailureCode {
    match error {
        LifecycleRuntimeError::Unavailable { .. } => LifecycleFailureCode::RuntimeUnavailable,
        LifecycleRuntimeError::InstanceNotManaged
        | LifecycleRuntimeError::Rejected { .. }
        | LifecycleRuntimeError::InvalidJobReference => LifecycleFailureCode::RuntimeRejected,
    }
}

fn completion_confirmed(
    operation: &LifecycleOperation,
    evidence: &LifecycleOperationEvidence,
) -> bool {
    if evidence.observation() != ObservationStatus::Observed {
        return false;
    }
    match operation.action() {
        LifecycleAction::Stop => evidence.process() == ProcessState::Inactive,
        LifecycleAction::Start => {
            evidence.process() == ProcessState::Active
                && evidence.readiness() == ReadinessStatus::Ready
        }
        LifecycleAction::Restart => {
            evidence.process() == ProcessState::Active
                && evidence.readiness() == ReadinessStatus::Ready
                && restart_evidence_changed(operation.initial_evidence(), evidence)
        }
    }
}

fn restart_evidence_changed(
    initial: &LifecycleOperationEvidence,
    current: &LifecycleOperationEvidence,
) -> bool {
    if initial.process() != ProcessState::Active {
        return true;
    }
    match (initial.invocation_id(), current.invocation_id()) {
        (Some(before), Some(after)) => before != after,
        (None, Some(_)) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use chrono::{DateTime, Utc};

    use super::*;
    use crate::server_instances::{
        application::{
            lifecycle_operations::{
                LifecycleOperationListQuery, LifecycleOperationRepositoryFuture,
            },
            lifecycle_runtime::LifecycleRuntimeFuture,
        },
        domain::{
            InstanceCapabilities, InstanceClassification, InstanceEnvironment, InstanceKind,
            InstanceObservability, InstanceReadiness, LifecycleOperationVersion, ServerInstance,
            SystemdJobReference,
        },
    };

    struct TestRegistry {
        main: ServerInstance,
        managed: ServerInstance,
    }

    impl InstanceRegistry for TestRegistry {
        fn primary(&self) -> ServerInstance {
            self.main.clone()
        }

        fn get(&self, id: &ServerInstanceId) -> Option<ServerInstance> {
            [&self.main, &self.managed]
                .into_iter()
                .find(|instance| instance.id() == id)
                .cloned()
        }

        fn list(&self) -> Vec<ServerInstance> {
            vec![self.main.clone(), self.managed.clone()]
        }
    }

    #[derive(Default)]
    struct MemoryOperations(Mutex<Vec<LifecycleOperation>>);

    impl LifecycleOperationRepository for MemoryOperations {
        fn insert<'a>(
            &'a self,
            operation: &'a LifecycleOperation,
        ) -> LifecycleOperationRepositoryFuture<'a, ()> {
            Box::pin(async move {
                let mut operations = self.0.lock().unwrap();
                let duplicate_key = operations.iter().any(|stored| {
                    stored.actor_id() == operation.actor_id()
                        && stored.idempotency_key() == operation.idempotency_key()
                });
                let active = operations.iter().any(|stored| {
                    stored.instance_id() == operation.instance_id() && !stored.state().is_terminal()
                });
                if duplicate_key || active {
                    return Err(LifecycleOperationRepositoryError::AlreadyExists);
                }
                operations.push(operation.clone());
                Ok(())
            })
        }

        fn find_by_id<'a>(
            &'a self,
            operation_id: LifecycleOperationId,
        ) -> LifecycleOperationRepositoryFuture<'a, Option<LifecycleOperation>> {
            Box::pin(async move {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|operation| operation.id() == operation_id)
                    .cloned())
            })
        }

        fn find_by_idempotency_key<'a>(
            &'a self,
            actor_id: LifecycleActorId,
            idempotency_key: &'a IdempotencyKey,
        ) -> LifecycleOperationRepositoryFuture<'a, Option<LifecycleOperation>> {
            Box::pin(async move {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|operation| {
                        operation.actor_id() == actor_id
                            && operation.idempotency_key() == idempotency_key
                    })
                    .cloned())
            })
        }

        fn find_active_for_instance<'a>(
            &'a self,
            instance_id: &'a ServerInstanceId,
        ) -> LifecycleOperationRepositoryFuture<'a, Option<LifecycleOperation>> {
            Box::pin(async move {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|operation| {
                        operation.instance_id() == instance_id && !operation.state().is_terminal()
                    })
                    .cloned())
            })
        }

        fn list_for_instance<'a>(
            &'a self,
            instance_id: &'a ServerInstanceId,
            query: LifecycleOperationListQuery,
        ) -> LifecycleOperationRepositoryFuture<'a, Vec<LifecycleOperation>> {
            Box::pin(async move {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|operation| operation.instance_id() == instance_id)
                    .take(query.limit)
                    .cloned()
                    .collect())
            })
        }

        fn save<'a>(
            &'a self,
            operation: &'a LifecycleOperation,
            expected_version: LifecycleOperationVersion,
        ) -> LifecycleOperationRepositoryFuture<'a, ()> {
            Box::pin(async move {
                let mut operations = self.0.lock().unwrap();
                let Some(stored) = operations
                    .iter_mut()
                    .find(|stored| stored.id() == operation.id())
                else {
                    return Err(LifecycleOperationRepositoryError::ConcurrentModification);
                };
                if stored.version() != expected_version
                    || operation.version().get() != expected_version.get() + 1
                {
                    return Err(LifecycleOperationRepositoryError::ConcurrentModification);
                }
                *stored = operation.clone();
                Ok(())
            })
        }
    }

    struct MutableStates(Mutex<InstanceRuntimeState>);

    impl RuntimeStateReader for MutableStates {
        fn get(
            &self,
            instance_id: &ServerInstanceId,
        ) -> Result<Option<InstanceRuntimeState>, RuntimeStateRepositoryError> {
            let state = self.0.lock().unwrap().clone();
            Ok((state.instance_id() == instance_id).then_some(state))
        }
    }

    struct FixedClock(Mutex<DateTime<Utc>>);

    impl LifecycleOperationClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }
    }

    struct FixedId(LifecycleOperationId);

    impl LifecycleOperationIdGenerator for FixedId {
        fn next_id(&self) -> LifecycleOperationId {
            self.0
        }
    }

    struct RecordingRuntime {
        calls: AtomicUsize,
        result: Mutex<Result<SystemdJobReference, LifecycleRuntimeError>>,
    }

    impl LifecycleRuntime for RecordingRuntime {
        fn dispatch<'a>(
            &'a self,
            _instance_id: &'a ServerInstanceId,
            _action: LifecycleAction,
        ) -> LifecycleRuntimeFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.result.lock().unwrap().clone()
            })
        }
    }

    struct Fixture {
        service: LifecycleOperationService,
        operations: Arc<MemoryOperations>,
        runtime: Arc<RecordingRuntime>,
        states: Arc<MutableStates>,
        clock: Arc<FixedClock>,
    }

    fn fixture(action_result: Result<SystemdJobReference, LifecycleRuntimeError>) -> Fixture {
        let at = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let main = ServerInstance::new(
            ServerInstanceId::new("main").unwrap(),
            "Main",
            InstanceClassification::new(
                InstanceKind::Primary,
                InstanceEnvironment::Production,
                InstanceManagement::External,
            ),
            10,
            InstanceCapabilities::primary(),
            InstanceObservability::new(InstanceReadiness::Uds, true),
        )
        .unwrap();
        let managed = ServerInstance::new(
            ServerInstanceId::new("test").unwrap(),
            "Test",
            InstanceClassification::new(
                InstanceKind::Auxiliary,
                InstanceEnvironment::Testing,
                InstanceManagement::Systemd,
            ),
            20,
            InstanceCapabilities::new([
                crate::server_instances::domain::InstanceCapability::Overview,
                crate::server_instances::domain::InstanceCapability::Lifecycle,
            ]),
            InstanceObservability::new(InstanceReadiness::Process, true),
        )
        .unwrap();
        let operations = Arc::new(MemoryOperations::default());
        let runtime = Arc::new(RecordingRuntime {
            calls: AtomicUsize::new(0),
            result: Mutex::new(action_result),
        });
        let states = Arc::new(MutableStates(Mutex::new(InstanceRuntimeState::observed(
            managed.id().clone(),
            ProcessState::Active,
            ReadinessStatus::Ready,
            at,
            Some(42),
            0,
            Some("invocation-before".into()),
            None,
        ))));
        let clock = Arc::new(FixedClock(Mutex::new(at)));
        let service = LifecycleOperationService::new(
            Arc::new(TestRegistry { main, managed }),
            operations.clone(),
            runtime.clone(),
            states.clone(),
            clock.clone(),
            Arc::new(FixedId(LifecycleOperationId::new())),
            Duration::from_secs(30),
        )
        .unwrap();
        Fixture {
            service,
            operations,
            runtime,
            states,
            clock,
        }
    }

    fn subject(role: UserRole, actor: i64) -> LifecycleSubject {
        LifecycleSubject::new(
            LifecycleActorId::new(actor).unwrap(),
            "Developer",
            role,
            vec![role],
        )
    }

    fn command(action: LifecycleAction, key: &str) -> LifecycleCommand {
        LifecycleCommand {
            instance_id: ServerInstanceId::new("test").unwrap(),
            action,
            idempotency_key: IdempotencyKey::new(key).unwrap(),
        }
    }

    fn successful_job() -> Result<SystemdJobReference, LifecycleRuntimeError> {
        Ok(SystemdJobReference::new("/org/freedesktop/systemd1/job/42").unwrap())
    }

    #[tokio::test]
    async fn persists_each_pre_dispatch_transition_and_replays_without_a_second_command() {
        let fixture = fixture(successful_job());
        let subject = subject(UserRole::Developer, 42);
        let first = fixture
            .service
            .request(&subject, command(LifecycleAction::Restart, "request-1"))
            .await
            .unwrap();
        let second = fixture
            .service
            .request(&subject, command(LifecycleAction::Restart, "request-1"))
            .await
            .unwrap();

        assert_eq!(first.disposition, LifecycleCommandDisposition::Created);
        assert_eq!(second.disposition, LifecycleCommandDisposition::Replayed);
        assert_eq!(first.operation.id(), second.operation.id());
        assert!(matches!(
            first.operation.state(),
            LifecycleOperationState::WaitingForState { .. }
        ));
        assert_eq!(first.operation.version().get(), 2);
        assert_eq!(fixture.runtime.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rejects_key_reuse_for_another_payload_and_serializes_active_operations() {
        let fixture = fixture(successful_job());
        let developer = subject(UserRole::Developer, 42);
        let first = fixture
            .service
            .request(&developer, command(LifecycleAction::Start, "request-1"))
            .await
            .unwrap();

        assert!(matches!(
            fixture
                .service
                .request(&developer, command(LifecycleAction::Stop, "request-1"))
                .await,
            Err(LifecycleOperationServiceError::IdempotencyConflict { .. })
        ));
        assert_eq!(
            match fixture
                .service
                .request(
                    &subject(UserRole::Developer, 43),
                    command(LifecycleAction::Stop, "request-2"),
                )
                .await
            {
                Err(LifecycleOperationServiceError::ActiveOperation { operation_id }) => {
                    operation_id
                }
                result => panic!("unexpected result: {result:?}"),
            },
            first.operation.id()
        );
        assert_eq!(fixture.runtime.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn enforces_developer_and_systemd_management_before_persistence() {
        let fixture = fixture(successful_job());
        assert!(matches!(
            fixture
                .service
                .request(
                    &subject(UserRole::Admin, 42),
                    command(LifecycleAction::Start, "request-1"),
                )
                .await,
            Err(LifecycleOperationServiceError::Forbidden)
        ));

        let mut external = command(LifecycleAction::Start, "request-2");
        external.instance_id = ServerInstanceId::new("main").unwrap();
        assert!(matches!(
            fixture
                .service
                .request(&subject(UserRole::Developer, 42), external)
                .await,
            Err(LifecycleOperationServiceError::InstanceNotManaged)
        ));
        assert!(fixture.operations.0.lock().unwrap().is_empty());
        assert_eq!(fixture.runtime.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn persists_runtime_rejection_as_a_terminal_operation() {
        let fixture = fixture(Err(LifecycleRuntimeError::Rejected {
            message: "access denied".into(),
        }));
        let result = fixture
            .service
            .request(
                &subject(UserRole::Developer, 42),
                command(LifecycleAction::Start, "request-1"),
            )
            .await
            .unwrap();

        assert_eq!(
            result.operation.state(),
            &LifecycleOperationState::Failed {
                code: LifecycleFailureCode::RuntimeRejected
            }
        );
        assert_eq!(result.operation.version().get(), 2);
    }

    #[tokio::test]
    async fn restart_reconciliation_requires_a_new_observed_invocation() {
        let fixture = fixture(successful_job());
        let result = fixture
            .service
            .request(
                &subject(UserRole::Developer, 42),
                command(LifecycleAction::Restart, "request-1"),
            )
            .await
            .unwrap();

        let unchanged = fixture
            .service
            .reconcile(result.operation.id())
            .await
            .unwrap();
        assert!(!unchanged.changed);

        let at = fixture.clock.now();
        *fixture.states.0.lock().unwrap() = InstanceRuntimeState::observed(
            ServerInstanceId::new("test").unwrap(),
            ProcessState::Active,
            ReadinessStatus::Ready,
            at,
            Some(43),
            0,
            Some("invocation-after".into()),
            None,
        );
        let completed = fixture
            .service
            .reconcile(result.operation.id())
            .await
            .unwrap();
        assert!(completed.changed);
        assert_eq!(
            completed.operation.state(),
            &LifecycleOperationState::Succeeded
        );
    }

    #[tokio::test]
    async fn reconciliation_times_out_without_fresh_evidence() {
        let fixture = fixture(successful_job());
        let result = fixture
            .service
            .request(
                &subject(UserRole::Developer, 42),
                command(LifecycleAction::Restart, "request-1"),
            )
            .await
            .unwrap();
        *fixture.clock.0.lock().unwrap() = result.operation.deadline();
        let timed_out = fixture
            .service
            .reconcile(result.operation.id())
            .await
            .unwrap();

        assert!(timed_out.changed);
        assert_eq!(
            timed_out.operation.state(),
            &LifecycleOperationState::TimedOut
        );
    }

    #[tokio::test]
    async fn retry_resumes_a_durably_requested_operation() {
        let fixture = fixture(successful_job());
        let actor = subject(UserRole::Developer, 42);
        let command = command(LifecycleAction::Start, "request-1");
        let at = fixture.clock.now();
        let requested = LifecycleOperation::request(
            LifecycleOperationId::new(),
            command.instance_id.clone(),
            command.action,
            actor.actor_id,
            actor.display_name.clone(),
            command.idempotency_key.clone(),
            request_fingerprint(&command.instance_id, command.action),
            LifecycleOperationEvidence::new(
                ProcessState::Active,
                ReadinessStatus::Ready,
                ObservationStatus::Observed,
                Some(at),
                Some(0),
                Some("invocation-before".into()),
            ),
            at,
            at + ChronoDuration::seconds(30),
        )
        .unwrap();
        fixture.operations.insert(&requested).await.unwrap();

        let resumed = fixture.service.request(&actor, command).await.unwrap();

        assert_eq!(resumed.operation.id(), requested.id());
        assert_eq!(resumed.disposition, LifecycleCommandDisposition::Replayed);
        assert!(matches!(
            resumed.operation.state(),
            LifecycleOperationState::WaitingForState { .. }
        ));
        assert_eq!(fixture.runtime.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn expired_requested_operation_is_timed_out_without_dispatch() {
        let fixture = fixture(successful_job());
        let actor = subject(UserRole::Developer, 42);
        let command = command(LifecycleAction::Start, "request-1");
        let at = fixture.clock.now();
        let requested = LifecycleOperation::request(
            LifecycleOperationId::new(),
            command.instance_id.clone(),
            command.action,
            actor.actor_id,
            actor.display_name.clone(),
            command.idempotency_key.clone(),
            request_fingerprint(&command.instance_id, command.action),
            LifecycleOperationEvidence::new(
                ProcessState::Active,
                ReadinessStatus::Ready,
                ObservationStatus::Observed,
                Some(at),
                Some(0),
                Some("invocation-before".into()),
            ),
            at,
            at + ChronoDuration::seconds(30),
        )
        .unwrap();
        fixture.operations.insert(&requested).await.unwrap();
        *fixture.clock.0.lock().unwrap() = requested.deadline();

        let recovered = fixture
            .service
            .recover_active(&command.instance_id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(recovered.state(), &LifecycleOperationState::TimedOut);
        assert_eq!(fixture.runtime.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn reconciliation_recovers_a_command_accepted_before_job_persistence() {
        let fixture = fixture(successful_job());
        let at = fixture.clock.now();
        let mut operation = LifecycleOperation::request(
            LifecycleOperationId::new(),
            ServerInstanceId::new("test").unwrap(),
            LifecycleAction::Restart,
            LifecycleActorId::new(42).unwrap(),
            "Developer",
            IdempotencyKey::new("request-1").unwrap(),
            request_fingerprint(
                &ServerInstanceId::new("test").unwrap(),
                LifecycleAction::Restart,
            ),
            LifecycleOperationEvidence::new(
                ProcessState::Active,
                ReadinessStatus::Ready,
                ObservationStatus::Observed,
                Some(at),
                Some(0),
                Some("invocation-before".into()),
            ),
            at,
            at + ChronoDuration::seconds(30),
        )
        .unwrap();
        fixture.operations.insert(&operation).await.unwrap();
        let expected_version = operation.version();
        operation.begin_dispatch(at).unwrap();
        fixture
            .operations
            .save(&operation, expected_version)
            .await
            .unwrap();
        *fixture.states.0.lock().unwrap() = InstanceRuntimeState::observed(
            ServerInstanceId::new("test").unwrap(),
            ProcessState::Active,
            ReadinessStatus::Ready,
            at,
            Some(43),
            0,
            Some("invocation-after".into()),
            None,
        );

        let recovered = fixture.service.reconcile(operation.id()).await.unwrap();

        assert!(recovered.changed);
        assert_eq!(
            recovered.operation.state(),
            &LifecycleOperationState::Succeeded
        );
        assert!(recovered.operation.final_evidence().is_some());
        assert_eq!(fixture.runtime.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn history_reads_require_developer_and_match_the_instance_path() {
        let fixture = fixture(successful_job());
        let developer = subject(UserRole::Developer, 42);
        let created = fixture
            .service
            .request(&developer, command(LifecycleAction::Start, "request-1"))
            .await
            .unwrap()
            .operation;
        let instance_id = ServerInstanceId::new("test").unwrap();

        let found = fixture
            .service
            .get(&developer, &instance_id, created.id())
            .await
            .unwrap();
        let listed = fixture
            .service
            .list(
                &developer,
                &instance_id,
                LifecycleOperationListQuery::new(None, 50).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(found.id(), created.id());
        assert_eq!(listed.len(), 1);
        assert!(matches!(
            fixture
                .service
                .get(&subject(UserRole::Admin, 42), &instance_id, created.id(),)
                .await,
            Err(LifecycleOperationServiceError::Forbidden)
        ));
        assert!(matches!(
            fixture
                .service
                .get(
                    &developer,
                    &ServerInstanceId::new("main").unwrap(),
                    created.id(),
                )
                .await,
            Err(LifecycleOperationServiceError::OperationNotFound)
        ));
    }
}
