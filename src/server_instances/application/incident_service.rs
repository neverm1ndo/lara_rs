use std::{future::Future, pin::Pin, sync::Arc};

use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::server_instances::{
    application::{
        incidents::{IncidentRepository, IncidentStoreError},
        registry::InstanceRegistry,
    },
    domain::{
        Incident, IncidentChange, IncidentConfidence, IncidentEvidence, IncidentFactId, IncidentId,
        IncidentKind, IncidentOperationalState, IncidentUnitName, InstanceCapability,
        InstanceManagement, InstanceRuntimeState, InvalidIncident, LifecycleAction,
        LifecycleOperation, LifecycleOperationState, ObservationStatus, ProcessState,
        ServerInstanceId, TerminationKind,
    },
};

pub type IncidentObservationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), IncidentObservationError>> + Send + 'a>>;

pub trait IncidentObservation: Send + Sync {
    fn observe<'a>(
        &'a self,
        unit_name: &'a str,
        previous: Option<&'a InstanceRuntimeState>,
        current: &'a InstanceRuntimeState,
    ) -> IncidentObservationFuture<'a>;
}

pub type IncidentOperationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<LifecycleOperation>, String>> + Send + 'a>>;

/// Returns recent persisted operations, including completed commands. An
/// active-only lookup misses a command completed before the observer refresh.
pub trait IncidentOperationLookup: Send + Sync {
    fn recent<'a>(&'a self, instance_id: &'a ServerInstanceId) -> IncidentOperationFuture<'a>;
}

pub struct IncidentObservationService {
    registry: Arc<dyn InstanceRegistry>,
    incidents: Arc<dyn IncidentRepository>,
    operations: Arc<dyn IncidentOperationLookup>,
}

impl IncidentObservationService {
    pub fn new(
        registry: Arc<dyn InstanceRegistry>,
        incidents: Arc<dyn IncidentRepository>,
        operations: Arc<dyn IncidentOperationLookup>,
    ) -> Self {
        Self {
            registry,
            incidents,
            operations,
        }
    }

    async fn process(
        &self,
        unit_name: &str,
        previous: Option<&InstanceRuntimeState>,
        current: &InstanceRuntimeState,
    ) -> Result<(), IncidentObservationError> {
        let Some(instance) = self.registry.get(current.instance_id()) else {
            return Ok(());
        };
        if instance.management() != InstanceManagement::Systemd
            || !instance
                .capabilities()
                .contains(InstanceCapability::Incidents)
            || !instance.observability().incident_tracking()
        {
            return Ok(());
        }
        let Some(previous) = previous else {
            return Ok(());
        };
        if previous.instance_id() != current.instance_id()
            || previous.observation() != ObservationStatus::Observed
            || current.observation() != ObservationStatus::Observed
            || current
                .observed_at()
                .is_none_or(|at| previous.observed_at().is_some_and(|before| at < before))
        {
            return Ok(());
        }
        if previous.process() == current.process()
            && previous.restart_count() == current.restart_count()
            && previous.invocation_id() == current.invocation_id()
            && previous.last_termination() == current.last_termination()
        {
            return Ok(());
        }

        let unit_name = IncidentUnitName::new(unit_name)?;
        let fact_id = live_fact_id(previous, current, &unit_name)?;
        if self
            .incidents
            .by_fact(current.instance_id(), unit_name.as_str(), &fact_id)
            .await?
            .is_some()
        {
            return Ok(());
        }

        if let Some(mut active) = self
            .incidents
            .active_for_instance(current.instance_id())
            .await?
        {
            let eligible = matches!(
                (active.operational_state(), current.process()),
                (_, ProcessState::Active)
                    | (IncidentOperationalState::Open, ProcessState::Activating)
                    | (
                        IncidentOperationalState::Recovering,
                        ProcessState::Failed | ProcessState::Inactive
                    )
            );
            if !eligible {
                return Ok(());
            }
            let evidence = evidence(current, &unit_name, fact_id)?;
            let at = Utc::now().max(active.updated_at());
            let expected = active.version();
            let change = match current.process() {
                ProcessState::Activating
                    if active.operational_state() == IncidentOperationalState::Open =>
                {
                    active.begin_recovery(evidence, at)?
                }
                ProcessState::Active => active.resolve(evidence, at)?,
                ProcessState::Failed | ProcessState::Inactive
                    if active.operational_state() == IncidentOperationalState::Recovering =>
                {
                    active.recovery_failed(evidence, at)?
                }
                _ => return Ok(()),
            };
            if change == IncidentChange::Applied {
                self.incidents.save(&active, expected).await?;
            }
            return Ok(());
        }

        let Some(kind) = classify(previous, current) else {
            return Ok(());
        };
        if kind != IncidentKind::Outage || current.process() != ProcessState::Failed {
            let operations = self
                .operations
                .recent(current.instance_id())
                .await
                .map_err(IncidentObservationError::Operations)?;
            if operations
                .iter()
                .any(|operation| planned_transition(operation, previous, current))
            {
                return Ok(());
            }
        }
        let opening = evidence(current, &unit_name, fact_id.clone())?;
        let incident = Incident::open(
            IncidentId::new(),
            current.instance_id().clone(),
            kind,
            opening,
        )?;
        match self.incidents.insert(&incident).await {
            Ok(()) => Ok(()),
            Err(IncidentStoreError::FactConflict) => {
                if self
                    .incidents
                    .by_fact(current.instance_id(), unit_name.as_str(), &fact_id)
                    .await?
                    .is_some()
                {
                    Ok(())
                } else {
                    Err(IncidentStoreError::FactConflict.into())
                }
            }
            Err(IncidentStoreError::ActiveConflict) => {
                if self
                    .incidents
                    .active_for_instance(current.instance_id())
                    .await?
                    .is_some()
                {
                    Ok(())
                } else {
                    Err(IncidentStoreError::ActiveConflict.into())
                }
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl IncidentObservation for IncidentObservationService {
    fn observe<'a>(
        &'a self,
        unit_name: &'a str,
        previous: Option<&'a InstanceRuntimeState>,
        current: &'a InstanceRuntimeState,
    ) -> IncidentObservationFuture<'a> {
        Box::pin(self.process(unit_name, previous, current))
    }
}

fn classify(
    previous: &InstanceRuntimeState,
    current: &InstanceRuntimeState,
) -> Option<IncidentKind> {
    match current.process() {
        ProcessState::Failed if previous.process() != ProcessState::Failed => {
            Some(IncidentKind::Outage)
        }
        ProcessState::Inactive
            if matches!(
                previous.process(),
                ProcessState::Active
                    | ProcessState::Activating
                    | ProcessState::Deactivating
                    | ProcessState::Failed
            ) =>
        {
            if current.last_termination().is_some_and(|termination| {
                !matches!(
                    termination.kind(),
                    TerminationKind::Clean | TerminationKind::Unknown
                )
            }) {
                Some(IncidentKind::Outage)
            } else {
                Some(IncidentKind::UnplannedStop)
            }
        }
        ProcessState::Active
            if previous.process() == ProcessState::Active
                && (previous
                    .invocation_id()
                    .zip(current.invocation_id())
                    .is_some_and(|(old, new)| old != new)
                    || previous
                        .restart_count()
                        .zip(current.restart_count())
                        .is_some_and(|(old, new)| new > old)) =>
        {
            Some(IncidentKind::UnexpectedRestart)
        }
        _ => None,
    }
}

fn planned_transition(
    operation: &LifecycleOperation,
    previous: &InstanceRuntimeState,
    current: &InstanceRuntimeState,
) -> bool {
    let Some(observed_at) = current.observed_at() else {
        return false;
    };
    if !matches!(
        operation.state(),
        LifecycleOperationState::WaitingForState { .. } | LifecycleOperationState::Succeeded
    ) || observed_at < operation.created_at()
        || observed_at > operation.deadline() + Duration::seconds(30)
        || previous
            .invocation_id()
            .zip(operation.initial_evidence().invocation_id())
            .is_none_or(|(observed, expected)| observed != expected)
        || current.process() == ProcessState::Failed
        || current.last_termination().is_some_and(|termination| {
            !matches!(
                termination.kind(),
                TerminationKind::Clean | TerminationKind::Unknown
            )
        })
    {
        return false;
    }
    let target_matches = match operation.action() {
        LifecycleAction::Stop => current.process() == ProcessState::Inactive,
        LifecycleAction::Restart => matches!(
            current.process(),
            ProcessState::Inactive | ProcessState::Active
        ),
        LifecycleAction::Start => false,
    };
    if !target_matches {
        return false;
    }
    match operation.state() {
        LifecycleOperationState::Succeeded => {
            operation.final_evidence().is_some_and(|final_state| {
                final_state.process() == current.process()
                    && (current.process() != ProcessState::Active
                        || final_state.invocation_id() == current.invocation_id())
            })
        }
        LifecycleOperationState::WaitingForState { .. } => true,
        _ => false,
    }
}

fn evidence(
    current: &InstanceRuntimeState,
    unit_name: &IncidentUnitName,
    fact_id: IncidentFactId,
) -> Result<IncidentEvidence, IncidentObservationError> {
    Ok(IncidentEvidence::new(
        fact_id,
        unit_name.clone(),
        current.observed_at().ok_or(InvalidIncident::Evidence)?,
        current.process(),
        current.invocation_id().map(str::to_owned),
        current.restart_count(),
        current.last_termination().cloned(),
        IncidentConfidence::Inferred,
    )?)
}

fn live_fact_id(
    previous: &InstanceRuntimeState,
    current: &InstanceRuntimeState,
    unit: &IncidentUnitName,
) -> Result<IncidentFactId, InvalidIncident> {
    let mut digest = Sha256::new();
    digest.update(b"incident-live-v1");
    for value in [previous.instance_id().as_str(), unit.as_str()] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    for state in [previous, current] {
        let process = match state.process() {
            ProcessState::Unknown => 0,
            ProcessState::Inactive => 1,
            ProcessState::Activating => 2,
            ProcessState::Active => 3,
            ProcessState::Deactivating => 4,
            ProcessState::Failed => 5,
        };
        digest.update([process]);
        let invocation = state.invocation_id().unwrap_or("");
        digest.update((invocation.len() as u64).to_be_bytes());
        digest.update(invocation.as_bytes());
        match state.restart_count() {
            Some(count) => {
                digest.update([1]);
                digest.update(count.to_be_bytes());
            }
            None => digest.update([0]),
        }
        match state.last_termination() {
            Some(termination) => {
                let kind = match termination.kind() {
                    TerminationKind::Clean => 1,
                    TerminationKind::ExitCode => 2,
                    TerminationKind::Signal => 3,
                    TerminationKind::CoreDump => 4,
                    TerminationKind::Timeout => 5,
                    TerminationKind::Watchdog => 6,
                    TerminationKind::ResourceFailure => 7,
                    TerminationKind::StartLimit => 8,
                    TerminationKind::Unknown => 9,
                };
                digest.update([kind]);
                if let Some(status) = termination.status() {
                    digest.update([1]);
                    digest.update(status.to_be_bytes());
                } else {
                    digest.update([0]);
                }
            }
            None => digest.update([0]),
        }
    }
    IncidentFactId::live(format!("{:x}", digest.finalize()))
}

#[derive(Debug, Error)]
pub enum IncidentObservationError {
    #[error(transparent)]
    Store(#[from] IncidentStoreError),
    #[error(transparent)]
    Domain(#[from] InvalidIncident),
    #[error("lifecycle operation lookup failed: {0}")]
    Operations(String),
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use chrono::DateTime;

    use super::*;
    use crate::server_instances::domain::{
        IdempotencyKey, IncidentReviewState, InstanceCapabilities, InstanceClassification,
        InstanceEnvironment, InstanceKind, InstanceObservability, InstanceReadiness,
        LifecycleActorId, LifecycleOperationEvidence, LifecycleOperationId, ReadinessStatus,
        RequestFingerprint, ServerInstance, SystemdJobReference, TerminationEvidence,
    };

    const UNIT: &str = "lara-game@test.service";

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + seconds, 0).unwrap()
    }

    fn state(
        seconds: i64,
        process: ProcessState,
        invocation: &str,
        restart_count: u32,
        termination: Option<TerminationEvidence>,
    ) -> InstanceRuntimeState {
        InstanceRuntimeState::observed(
            ServerInstanceId::new("test").unwrap(),
            process,
            if process == ProcessState::Active {
                ReadinessStatus::Ready
            } else {
                ReadinessStatus::NotReady
            },
            at(seconds),
            None,
            restart_count,
            Some(invocation.into()),
            termination,
        )
    }

    struct Registry(ServerInstance);

    impl InstanceRegistry for Registry {
        fn primary(&self) -> ServerInstance {
            self.0.clone()
        }
        fn get(&self, id: &ServerInstanceId) -> Option<ServerInstance> {
            (self.0.id() == id).then(|| self.0.clone())
        }
        fn list(&self) -> Vec<ServerInstance> {
            vec![self.0.clone()]
        }
    }

    struct MemoryIncidents(Mutex<Vec<Incident>>);

    impl IncidentRepository for MemoryIncidents {
        fn insert<'a>(
            &'a self,
            incident: &'a Incident,
        ) -> crate::server_instances::application::incidents::IncidentStoreFuture<'a, ()> {
            Box::pin(async move {
                let mut records = self.0.lock().unwrap();
                if records.iter().any(|record| record.id() == incident.id()) {
                    return Err(IncidentStoreError::FactConflict);
                }
                records.push(incident.clone());
                Ok(())
            })
        }
        fn by_id<'a>(
            &'a self,
            id: IncidentId,
        ) -> crate::server_instances::application::incidents::IncidentStoreFuture<
            'a,
            Option<Incident>,
        > {
            Box::pin(async move {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|record| record.id() == id)
                    .cloned())
            })
        }
        fn by_fact<'a>(
            &'a self,
            instance_id: &'a ServerInstanceId,
            _unit_name: &'a str,
            fact_id: &'a IncidentFactId,
        ) -> crate::server_instances::application::incidents::IncidentStoreFuture<
            'a,
            Option<Incident>,
        > {
            Box::pin(async move {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|record| {
                        record.instance_id() == instance_id
                            && record
                                .evidence()
                                .iter()
                                .any(|evidence| evidence.fact_id() == fact_id)
                    })
                    .cloned())
            })
        }
        fn active_for_instance<'a>(
            &'a self,
            instance_id: &'a ServerInstanceId,
        ) -> crate::server_instances::application::incidents::IncidentStoreFuture<
            'a,
            Option<Incident>,
        > {
            Box::pin(async move {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|record| {
                        record.instance_id() == instance_id
                            && record.operational_state() != IncidentOperationalState::Resolved
                    })
                    .cloned())
            })
        }
        fn save<'a>(
            &'a self,
            incident: &'a Incident,
            expected_version: u64,
        ) -> crate::server_instances::application::incidents::IncidentStoreFuture<'a, ()> {
            Box::pin(async move {
                let mut records = self.0.lock().unwrap();
                let stored = records
                    .iter_mut()
                    .find(|record| record.id() == incident.id())
                    .ok_or(IncidentStoreError::ConcurrentModification)?;
                if stored.version() != expected_version {
                    return Err(IncidentStoreError::ConcurrentModification);
                }
                *stored = incident.clone();
                Ok(())
            })
        }
    }

    struct MemoryOperations(Vec<LifecycleOperation>);

    impl IncidentOperationLookup for MemoryOperations {
        fn recent<'a>(&'a self, _instance_id: &'a ServerInstanceId) -> IncidentOperationFuture<'a> {
            Box::pin(async move { Ok(self.0.clone()) })
        }
    }

    fn service(
        tracking: bool,
        operations: Vec<LifecycleOperation>,
    ) -> (IncidentObservationService, Arc<MemoryIncidents>) {
        let instance = ServerInstance::new(
            ServerInstanceId::new("test").unwrap(),
            "Test",
            InstanceClassification::new(
                InstanceKind::Auxiliary,
                InstanceEnvironment::Testing,
                InstanceManagement::Systemd,
            ),
            10,
            InstanceCapabilities::new([
                InstanceCapability::Overview,
                InstanceCapability::Lifecycle,
                InstanceCapability::Incidents,
            ]),
            InstanceObservability::new(InstanceReadiness::Process, tracking),
        )
        .unwrap();
        let incidents = Arc::new(MemoryIncidents(Mutex::new(Vec::new())));
        (
            IncidentObservationService::new(
                Arc::new(Registry(instance)),
                incidents.clone(),
                Arc::new(MemoryOperations(operations)),
            ),
            incidents,
        )
    }

    fn operation(
        action: LifecycleAction,
        previous: &InstanceRuntimeState,
        final_state: Option<&InstanceRuntimeState>,
    ) -> LifecycleOperation {
        let initial = LifecycleOperationEvidence::new(
            previous.process(),
            previous.readiness(),
            previous.observation(),
            previous.observed_at(),
            previous.restart_count(),
            previous.invocation_id().map(str::to_owned),
        );
        let mut operation = LifecycleOperation::request(
            LifecycleOperationId::new(),
            previous.instance_id().clone(),
            action,
            LifecycleActorId::new(42).unwrap(),
            "Developer",
            IdempotencyKey::new("planned").unwrap(),
            RequestFingerprint::new("a".repeat(64)).unwrap(),
            initial,
            at(1),
            at(100),
        )
        .unwrap();
        operation.begin_dispatch(at(2)).unwrap();
        operation
            .wait_for_state(
                SystemdJobReference::new("/org/freedesktop/systemd1/job/1").unwrap(),
                at(3),
            )
            .unwrap();
        if let Some(final_state) = final_state {
            operation
                .succeed(
                    LifecycleOperationEvidence::new(
                        final_state.process(),
                        final_state.readiness(),
                        final_state.observation(),
                        final_state.observed_at(),
                        final_state.restart_count(),
                        final_state.invocation_id().map(str::to_owned),
                    ),
                    at(9),
                )
                .unwrap();
        }
        operation
    }

    #[tokio::test]
    async fn crash_and_automatic_recovery_leave_one_unreviewed_incident() {
        let (service, records) = service(true, vec![]);
        let active = state(0, ProcessState::Active, "invocation-a", 0, None);
        let failed = state(
            4,
            ProcessState::Failed,
            "invocation-a",
            0,
            Some(TerminationEvidence::new(TerminationKind::ExitCode, Some(1))),
        );
        let starting = state(6, ProcessState::Activating, "invocation-b", 1, None);
        let recovered = state(8, ProcessState::Active, "invocation-b", 1, None);

        service.observe(UNIT, None, &active).await.unwrap();
        assert!(records.0.lock().unwrap().is_empty());
        service.observe(UNIT, Some(&active), &failed).await.unwrap();
        service.observe(UNIT, Some(&active), &failed).await.unwrap();
        service
            .observe(UNIT, Some(&failed), &starting)
            .await
            .unwrap();
        service
            .observe(UNIT, Some(&starting), &recovered)
            .await
            .unwrap();

        let records = records.0.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind(), IncidentKind::Outage);
        assert_eq!(
            records[0].operational_state(),
            IncidentOperationalState::Resolved
        );
        assert_eq!(records[0].review_state(), IncidentReviewState::Unreviewed);
        assert_eq!(records[0].evidence().len(), 3);
    }

    #[tokio::test]
    async fn planned_restart_is_suppressed_but_independent_failure_is_recorded() {
        let active = state(0, ProcessState::Active, "invocation-a", 0, None);
        let restarted = state(8, ProcessState::Active, "invocation-b", 1, None);
        let planned = operation(LifecycleAction::Restart, &active, Some(&restarted));
        let (service, records) = service(true, vec![planned]);

        service
            .observe(UNIT, Some(&active), &restarted)
            .await
            .unwrap();
        assert!(records.0.lock().unwrap().is_empty());
        let failed = state(
            9,
            ProcessState::Failed,
            "invocation-b",
            1,
            Some(TerminationEvidence::new(TerminationKind::Signal, Some(11))),
        );
        service
            .observe(UNIT, Some(&restarted), &failed)
            .await
            .unwrap();
        assert_eq!(records.0.lock().unwrap()[0].kind(), IncidentKind::Outage);
    }

    #[tokio::test]
    async fn planned_stop_and_stale_observations_do_not_create_incidents() {
        let active = state(0, ProcessState::Active, "invocation-a", 0, None);
        let stopped = state(
            8,
            ProcessState::Inactive,
            "invocation-a",
            0,
            Some(TerminationEvidence::new(TerminationKind::Clean, Some(0))),
        );
        let planned = operation(LifecycleAction::Stop, &active, None);
        let (service, records) = service(true, vec![planned]);
        service
            .observe(UNIT, Some(&active), &stopped)
            .await
            .unwrap();
        service
            .observe(UNIT, Some(&active.into_stale()), &stopped)
            .await
            .unwrap();
        assert!(records.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unplanned_restart_and_tracking_switch_behave_independently() {
        let active = state(0, ProcessState::Active, "invocation-a", 0, None);
        let restarted = state(5, ProcessState::Active, "invocation-b", 1, None);
        let (enabled, records) = service(true, vec![]);
        enabled
            .observe(UNIT, Some(&active), &restarted)
            .await
            .unwrap();
        assert_eq!(
            records.0.lock().unwrap()[0].kind(),
            IncidentKind::UnexpectedRestart
        );

        let (disabled, records) = service(false, vec![]);
        disabled
            .observe(UNIT, Some(&active), &restarted)
            .await
            .unwrap();
        assert!(records.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn external_stop_is_recorded_without_inventing_a_crash_cause() {
        let (service, records) = service(true, vec![]);
        let active = state(0, ProcessState::Active, "invocation-a", 0, None);
        let stopped = state(
            5,
            ProcessState::Inactive,
            "invocation-a",
            0,
            Some(TerminationEvidence::new(TerminationKind::Clean, Some(0))),
        );

        service
            .observe(UNIT, Some(&active), &stopped)
            .await
            .unwrap();
        let records = records.0.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind(), IncidentKind::UnplannedStop);
        assert_eq!(
            records[0].cause(),
            crate::server_instances::domain::IncidentCause::Unknown
        );
    }

    #[tokio::test]
    async fn failed_recovery_attempt_returns_to_open_then_resolves() {
        let (service, records) = service(true, vec![]);
        let active = state(0, ProcessState::Active, "invocation-a", 0, None);
        let failed = state(
            4,
            ProcessState::Failed,
            "invocation-a",
            0,
            Some(TerminationEvidence::new(TerminationKind::ExitCode, Some(1))),
        );
        let starting = state(5, ProcessState::Activating, "invocation-b", 1, None);
        let failed_again = state(
            6,
            ProcessState::Failed,
            "invocation-b",
            1,
            Some(TerminationEvidence::new(TerminationKind::ExitCode, Some(2))),
        );
        let starting_again = state(7, ProcessState::Activating, "invocation-c", 2, None);
        let recovered = state(8, ProcessState::Active, "invocation-c", 2, None);

        for (before, after) in [
            (&active, &failed),
            (&failed, &starting),
            (&starting, &failed_again),
            (&failed_again, &starting_again),
            (&starting_again, &recovered),
        ] {
            service.observe(UNIT, Some(before), after).await.unwrap();
        }
        let incident = records.0.lock().unwrap()[0].clone();
        assert_eq!(
            incident.operational_state(),
            IncidentOperationalState::Resolved
        );
        assert_eq!(incident.evidence().len(), 5);
        assert_eq!(Incident::rehydrate(incident.snapshot()).unwrap(), incident);
    }
}
