use std::{sync::Arc, time::Duration};

use chrono::Utc;
use futures_util::StreamExt;
use thiserror::Error;
use tokio::sync::watch;
use tracing::{debug, info, warn};
use zbus::{Connection, Proxy, zvariant::OwnedObjectPath};

use crate::server_instances::{
    application::{
        lifecycle_events::{
            LifecycleEventDelivery, ServerInstanceEvent, ServerInstanceStateChangedEvent,
        },
        runtime_state::{RuntimeStateRepositoryError, RuntimeStateWriter},
    },
    domain::{
        InstanceReadiness, InstanceRuntimeState, ProcessState, ReadinessStatus, ServerInstanceId,
        TerminationEvidence, TerminationKind,
    },
};

const SYSTEMD_DESTINATION: &str = "org.freedesktop.systemd1";
const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const SYSTEMD_UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SYSTEMD_SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";
const DBUS_PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdObservationTarget {
    instance_id: ServerInstanceId,
    unit_name: String,
    readiness_mode: InstanceReadiness,
}

impl SystemdObservationTarget {
    pub fn new(
        instance_id: ServerInstanceId,
        unit_name: impl Into<String>,
        readiness_mode: InstanceReadiness,
    ) -> Self {
        Self {
            instance_id,
            unit_name: unit_name.into(),
            readiness_mode,
        }
    }
}

pub struct SystemdObserverWorker {
    targets: Vec<SystemdObservationTarget>,
    states: Arc<dyn RuntimeStateWriter>,
    events: Option<Arc<dyn LifecycleEventDelivery>>,
}

impl SystemdObserverWorker {
    pub fn new(
        targets: Vec<SystemdObservationTarget>,
        states: Arc<dyn RuntimeStateWriter>,
    ) -> Self {
        Self {
            targets,
            states,
            events: None,
        }
    }

    pub fn with_event_delivery(mut self, events: Arc<dyn LifecycleEventDelivery>) -> Self {
        self.events = Some(events);
        self
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        if self.targets.is_empty() {
            return;
        }

        info!(
            target_count = self.targets.len(),
            "systemd shadow observer started"
        );
        let mut tasks = tokio::task::JoinSet::new();
        for target in self.targets {
            let states = Arc::clone(&self.states);
            let events = self.events.clone();
            let target_shutdown = shutdown.clone();
            tasks.spawn(async move {
                observe_target(target, states, events, target_shutdown).await;
            });
        }

        if !*shutdown.borrow() {
            let _ = shutdown.changed().await;
        }
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                warn!(error = %error, "systemd observer task terminated unexpectedly");
            }
        }
        info!("systemd shadow observer stopped");
    }
}

async fn observe_target(
    target: SystemdObservationTarget,
    states: Arc<dyn RuntimeStateWriter>,
    events: Option<Arc<dyn LifecycleEventDelivery>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut last_state: Option<InstanceRuntimeState> = None;

    loop {
        if *shutdown.borrow() {
            return;
        }

        let result = observe_connected(
            &target,
            &states,
            events.as_ref(),
            &mut shutdown,
            &mut last_state,
        )
        .await;
        match result {
            Ok(()) => return,
            Err(error) => {
                if let Some(state) = last_state.clone() {
                    let stale = state.into_stale();
                    if let Err(store_error) = states.put(stale.clone()) {
                        warn!(
                            instance_id = %target.instance_id,
                            error = %store_error,
                            "failed to mark systemd snapshot as stale"
                        );
                    } else {
                        publish_state_event(events.as_ref(), &target, stale).await;
                    }
                }
                warn!(
                    instance_id = %target.instance_id,
                    unit = %target.unit_name,
                    error = %error,
                    "systemd observation interrupted; retrying"
                );
            }
        }

        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(RETRY_INTERVAL) => {}
        }
    }
}

async fn observe_connected(
    target: &SystemdObservationTarget,
    states: &Arc<dyn RuntimeStateWriter>,
    events: Option<&Arc<dyn LifecycleEventDelivery>>,
    shutdown: &mut watch::Receiver<bool>,
    last_state: &mut Option<InstanceRuntimeState>,
) -> Result<(), SystemdObserverError> {
    let connection = Connection::system().await?;
    let manager = Proxy::new(
        &connection,
        SYSTEMD_DESTINATION,
        SYSTEMD_MANAGER_PATH,
        SYSTEMD_MANAGER_INTERFACE,
    )
    .await?;
    manager.call_method("Subscribe", &()).await?;
    let path: OwnedObjectPath = manager
        .call("GetUnit", &(target.unit_name.as_str(),))
        .await?;
    let properties = Proxy::new(
        &connection,
        SYSTEMD_DESTINATION,
        path.as_str(),
        DBUS_PROPERTIES_INTERFACE,
    )
    .await?;
    let mut changes = properties.receive_signal("PropertiesChanged").await?;

    refresh(&connection, &path, target, states, events, last_state).await?;
    let mut reconciliation = tokio::time::interval(RECONCILE_INTERVAL);
    reconciliation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    reconciliation.tick().await;

    loop {
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            change = changes.next() => {
                if change.is_none() {
                    return Err(SystemdObserverError::SignalStreamEnded);
                }
                refresh(&connection, &path, target, states, events, last_state).await?;
            }
            _ = reconciliation.tick() => {
                refresh(&connection, &path, target, states, events, last_state).await?;
            }
        }
    }
}

async fn refresh(
    connection: &Connection,
    path: &OwnedObjectPath,
    target: &SystemdObservationTarget,
    states: &Arc<dyn RuntimeStateWriter>,
    events: Option<&Arc<dyn LifecycleEventDelivery>>,
    last_state: &mut Option<InstanceRuntimeState>,
) -> Result<(), SystemdObserverError> {
    let observation = read_unit(connection, path).await?;
    debug!(
        instance_id = %target.instance_id,
        unit = %target.unit_name,
        active_state = %observation.active_state,
        sub_state = %observation.sub_state,
        restart_count = observation.restart_count,
        "systemd state reconciled"
    );
    let state = observation.normalize(target, Utc::now());
    states.put(state.clone())?;
    if last_state
        .as_ref()
        .is_none_or(|previous| runtime_state_changed(previous, &state))
    {
        publish_state_event(events, target, state.clone()).await;
    }
    *last_state = Some(state);
    Ok(())
}

async fn publish_state_event(
    events: Option<&Arc<dyn LifecycleEventDelivery>>,
    target: &SystemdObservationTarget,
    state: InstanceRuntimeState,
) {
    let Some(events) = events else {
        return;
    };
    let event = ServerInstanceStateChangedEvent::new(state, target.readiness_mode, Utc::now());
    if let Err(error) = events
        .deliver(&ServerInstanceEvent::StateChanged(event))
        .await
    {
        warn!(
            instance_id = %target.instance_id,
            error = %error,
            "failed to publish realtime systemd state"
        );
    }
}

fn runtime_state_changed(previous: &InstanceRuntimeState, next: &InstanceRuntimeState) -> bool {
    previous.process() != next.process()
        || previous.readiness() != next.readiness()
        || previous.observation() != next.observation()
        || previous.main_pid() != next.main_pid()
        || previous.restart_count() != next.restart_count()
        || previous.invocation_id() != next.invocation_id()
        || previous.last_termination() != next.last_termination()
}

async fn read_unit(
    connection: &Connection,
    path: &OwnedObjectPath,
) -> Result<SystemdUnitObservation, zbus::Error> {
    // New proxies are deliberately created for every reconciliation. This
    // prevents a missed PropertiesChanged signal from leaving cached values
    // looking current forever.
    let unit = Proxy::new(
        connection,
        SYSTEMD_DESTINATION,
        path.as_str(),
        SYSTEMD_UNIT_INTERFACE,
    )
    .await?;
    let service = Proxy::new(
        connection,
        SYSTEMD_DESTINATION,
        path.as_str(),
        SYSTEMD_SERVICE_INTERFACE,
    )
    .await?;

    let (
        active_state,
        sub_state,
        invocation_id,
        main_pid,
        restart_count,
        result,
        exec_main_code,
        exec_main_status,
    ) = tokio::try_join!(
        unit.get_property::<String>("ActiveState"),
        unit.get_property::<String>("SubState"),
        unit.get_property::<Vec<u8>>("InvocationID"),
        service.get_property::<u32>("MainPID"),
        service.get_property::<u32>("NRestarts"),
        service.get_property::<String>("Result"),
        service.get_property::<i32>("ExecMainCode"),
        service.get_property::<i32>("ExecMainStatus"),
    )?;

    Ok(SystemdUnitObservation {
        active_state,
        sub_state,
        invocation_id,
        main_pid,
        restart_count,
        result,
        exec_main_code,
        exec_main_status,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SystemdUnitObservation {
    active_state: String,
    sub_state: String,
    invocation_id: Vec<u8>,
    main_pid: u32,
    restart_count: u32,
    result: String,
    exec_main_code: i32,
    exec_main_status: i32,
}

impl SystemdUnitObservation {
    fn normalize(
        self,
        target: &SystemdObservationTarget,
        observed_at: chrono::DateTime<Utc>,
    ) -> InstanceRuntimeState {
        let process = match self.active_state.as_str() {
            "inactive" => ProcessState::Inactive,
            "activating" => ProcessState::Activating,
            "active" | "reloading" | "refreshing" => ProcessState::Active,
            "deactivating" => ProcessState::Deactivating,
            "failed" => ProcessState::Failed,
            _ => ProcessState::Unknown,
        };
        let readiness = match (target.readiness_mode, process) {
            (InstanceReadiness::Process, ProcessState::Active) => ReadinessStatus::Ready,
            (InstanceReadiness::Process, ProcessState::Unknown) => ReadinessStatus::Unknown,
            (InstanceReadiness::Process, _) => ReadinessStatus::NotReady,
            (InstanceReadiness::Uds, _) => ReadinessStatus::Unknown,
        };

        InstanceRuntimeState::observed(
            target.instance_id.clone(),
            process,
            readiness,
            observed_at,
            (self.main_pid != 0).then_some(self.main_pid),
            self.restart_count,
            invocation_id_hex(&self.invocation_id),
            termination_evidence(&self),
        )
    }
}

fn invocation_id_hex(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.iter().all(|byte| *byte == 0) {
        return None;
    }
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Some(encoded)
}

fn termination_evidence(observation: &SystemdUnitObservation) -> Option<TerminationEvidence> {
    if observation.exec_main_code == 0 && observation.result == "success" {
        return None;
    }

    let kind = match observation.result.as_str() {
        "success" => TerminationKind::Clean,
        "exit-code" => TerminationKind::ExitCode,
        "signal" => TerminationKind::Signal,
        "core-dump" => TerminationKind::CoreDump,
        "timeout" => TerminationKind::Timeout,
        "watchdog" => TerminationKind::Watchdog,
        "resources" | "oom-kill" => TerminationKind::ResourceFailure,
        "start-limit-hit" => TerminationKind::StartLimit,
        _ => match observation.exec_main_code {
            1 => TerminationKind::ExitCode,
            2 => TerminationKind::Signal,
            3 => TerminationKind::CoreDump,
            _ => TerminationKind::Unknown,
        },
    };
    let status = (observation.exec_main_code != 0).then_some(observation.exec_main_status);
    Some(TerminationEvidence::new(kind, status))
}

#[derive(Debug, Error)]
enum SystemdObserverError {
    #[error("system D-Bus operation failed: {0}")]
    Dbus(#[from] zbus::Error),
    #[error(transparent)]
    StateStore(#[from] RuntimeStateRepositoryError),
    #[error("systemd property signal stream ended")]
    SignalStreamEnded,
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;

    use super::*;

    fn target(readiness: InstanceReadiness) -> SystemdObservationTarget {
        SystemdObservationTarget::new(
            ServerInstanceId::new("dev-dm").unwrap(),
            "lara-game@dev-dm.service",
            readiness,
        )
    }

    fn observation(active_state: &str, result: &str) -> SystemdUnitObservation {
        SystemdUnitObservation {
            active_state: active_state.into(),
            sub_state: "running".into(),
            invocation_id: (0_u8..16).collect(),
            main_pid: 42,
            restart_count: 3,
            result: result.into(),
            exec_main_code: 0,
            exec_main_status: 0,
        }
    }

    #[test]
    fn maps_process_readiness_without_treating_uds_as_process_readiness() {
        let at = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let process =
            observation("active", "success").normalize(&target(InstanceReadiness::Process), at);
        let uds = observation("active", "success").normalize(&target(InstanceReadiness::Uds), at);

        assert_eq!(process.process(), ProcessState::Active);
        assert_eq!(process.readiness(), ReadinessStatus::Ready);
        assert_eq!(process.main_pid(), Some(42));
        assert_eq!(process.restart_count(), Some(3));
        assert_eq!(
            process.invocation_id(),
            Some("000102030405060708090a0b0c0d0e0f")
        );
        assert_eq!(uds.readiness(), ReadinessStatus::Unknown);
    }

    #[test]
    fn maps_systemd_failure_evidence_without_raw_unit_details() {
        let mut failed = observation("failed", "exit-code");
        failed.main_pid = 0;
        failed.exec_main_code = 1;
        failed.exec_main_status = 203;
        let state = failed.normalize(
            &target(InstanceReadiness::Process),
            DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        );

        assert_eq!(state.process(), ProcessState::Failed);
        assert_eq!(state.readiness(), ReadinessStatus::NotReady);
        assert_eq!(state.main_pid(), None);
        assert_eq!(
            state.last_termination(),
            Some(&TerminationEvidence::new(
                TerminationKind::ExitCode,
                Some(203)
            ))
        );
    }

    #[test]
    fn maps_timeout_watchdog_resource_and_start_limit_results() {
        for (result, expected) in [
            ("timeout", TerminationKind::Timeout),
            ("watchdog", TerminationKind::Watchdog),
            ("oom-kill", TerminationKind::ResourceFailure),
            ("start-limit-hit", TerminationKind::StartLimit),
        ] {
            let mut raw = observation("failed", result);
            raw.exec_main_code = 1;
            raw.exec_main_status = 1;
            assert_eq!(termination_evidence(&raw).unwrap().kind(), expected);
        }
    }
}
