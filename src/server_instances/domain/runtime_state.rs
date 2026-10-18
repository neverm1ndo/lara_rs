use chrono::{DateTime, Utc};

use super::ServerInstanceId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Unknown,
    Inactive,
    Activating,
    Active,
    Deactivating,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessStatus {
    Unknown,
    NotReady,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationStatus {
    NotObserved,
    Observed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationKind {
    Clean,
    ExitCode,
    Signal,
    CoreDump,
    Timeout,
    Watchdog,
    ResourceFailure,
    StartLimit,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminationEvidence {
    kind: TerminationKind,
    status: Option<i32>,
}

impl TerminationEvidence {
    pub const fn new(kind: TerminationKind, status: Option<i32>) -> Self {
        Self { kind, status }
    }

    pub const fn kind(&self) -> TerminationKind {
        self.kind
    }

    pub const fn status(&self) -> Option<i32> {
        self.status
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceRuntimeState {
    instance_id: ServerInstanceId,
    process: ProcessState,
    readiness: ReadinessStatus,
    observation: ObservationStatus,
    observed_at: Option<DateTime<Utc>>,
    main_pid: Option<u32>,
    restart_count: Option<u32>,
    invocation_id: Option<String>,
    last_termination: Option<TerminationEvidence>,
}

impl InstanceRuntimeState {
    pub fn not_observed(instance_id: ServerInstanceId) -> Self {
        Self {
            instance_id,
            process: ProcessState::Unknown,
            readiness: ReadinessStatus::Unknown,
            observation: ObservationStatus::NotObserved,
            observed_at: None,
            main_pid: None,
            restart_count: None,
            invocation_id: None,
            last_termination: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observed(
        instance_id: ServerInstanceId,
        process: ProcessState,
        readiness: ReadinessStatus,
        observed_at: DateTime<Utc>,
        main_pid: Option<u32>,
        restart_count: u32,
        invocation_id: Option<String>,
        last_termination: Option<TerminationEvidence>,
    ) -> Self {
        Self {
            instance_id,
            process,
            readiness,
            observation: ObservationStatus::Observed,
            observed_at: Some(observed_at),
            main_pid: main_pid.filter(|pid| *pid != 0),
            restart_count: Some(restart_count),
            invocation_id: invocation_id.filter(|value| !value.trim().is_empty()),
            last_termination,
        }
    }

    pub fn instance_id(&self) -> &ServerInstanceId {
        &self.instance_id
    }

    pub const fn process(&self) -> ProcessState {
        self.process
    }

    pub const fn readiness(&self) -> ReadinessStatus {
        self.readiness
    }

    pub const fn observation(&self) -> ObservationStatus {
        self.observation
    }

    pub const fn observed_at(&self) -> Option<DateTime<Utc>> {
        self.observed_at
    }

    pub const fn main_pid(&self) -> Option<u32> {
        self.main_pid
    }

    pub const fn restart_count(&self) -> Option<u32> {
        self.restart_count
    }

    pub fn invocation_id(&self) -> Option<&str> {
        self.invocation_id.as_deref()
    }

    pub const fn last_termination(&self) -> Option<&TerminationEvidence> {
        self.last_termination.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_observed_is_distinct_from_offline() {
        let state = InstanceRuntimeState::not_observed(ServerInstanceId::new("main").unwrap());

        assert_eq!(state.process(), ProcessState::Unknown);
        assert_eq!(state.readiness(), ReadinessStatus::Unknown);
        assert_eq!(state.observation(), ObservationStatus::NotObserved);
        assert!(state.observed_at().is_none());
        assert!(state.restart_count().is_none());
    }

    #[test]
    fn observed_state_keeps_process_evidence() {
        let observed_at = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let state = InstanceRuntimeState::observed(
            ServerInstanceId::new("main").unwrap(),
            ProcessState::Failed,
            ReadinessStatus::NotReady,
            observed_at,
            None,
            3,
            Some("invocation-1".into()),
            Some(TerminationEvidence::new(TerminationKind::ExitCode, Some(1))),
        );

        assert_eq!(state.observation(), ObservationStatus::Observed);
        assert_eq!(state.observed_at(), Some(observed_at));
        assert_eq!(state.restart_count(), Some(3));
        assert_eq!(state.invocation_id(), Some("invocation-1"));
        assert_eq!(
            state.last_termination().unwrap().kind(),
            TerminationKind::ExitCode
        );
    }
}
