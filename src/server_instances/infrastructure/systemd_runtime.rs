use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};

use zbus::{Connection, Proxy, zvariant::OwnedObjectPath};

use crate::server_instances::{
    application::lifecycle_runtime::{
        LifecycleRuntime, LifecycleRuntimeError, LifecycleRuntimeFuture,
    },
    domain::{InstanceManagement, LifecycleAction, ServerInstanceId, SystemdJobReference},
};

use super::config_registry::ConfiguredInstanceRegistry;

const SYSTEMD_DESTINATION: &str = "org.freedesktop.systemd1";
const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const SYSTEMD_JOB_MODE: &str = "replace";

type ManagerFuture<'a> =
    Pin<Box<dyn Future<Output = Result<String, SystemdManagerError>> + Send + 'a>>;

trait SystemdManagerClient: Send + Sync {
    fn dispatch<'a>(&'a self, unit: &'a str, action: LifecycleAction) -> ManagerFuture<'a>;
}

#[derive(Debug, Default)]
struct ZbusSystemdManagerClient;

impl SystemdManagerClient for ZbusSystemdManagerClient {
    fn dispatch<'a>(&'a self, unit: &'a str, action: LifecycleAction) -> ManagerFuture<'a> {
        Box::pin(async move {
            let connection = Connection::system()
                .await
                .map_err(SystemdManagerError::unavailable)?;
            let manager = Proxy::new(
                &connection,
                SYSTEMD_DESTINATION,
                SYSTEMD_MANAGER_PATH,
                SYSTEMD_MANAGER_INTERFACE,
            )
            .await
            .map_err(SystemdManagerError::unavailable)?;
            let job: OwnedObjectPath = manager
                .call(method_name(action), &(unit, SYSTEMD_JOB_MODE))
                .await
                .map_err(SystemdManagerError::rejected)?;
            Ok(job.to_string())
        })
    }
}

/// systemd D-Bus adapter with an immutable instance-to-unit allowlist derived
/// from the validated configuration registry. HTTP or application payloads
/// can therefore never select an arbitrary unit.
pub struct SystemdLifecycleRuntime {
    units: BTreeMap<ServerInstanceId, String>,
    manager: Arc<dyn SystemdManagerClient>,
}

impl SystemdLifecycleRuntime {
    pub fn from_registry(registry: &ConfiguredInstanceRegistry) -> Self {
        let units = registry
            .systemd_managed()
            .map(|configured| {
                let descriptor = configured.descriptor();
                debug_assert_eq!(descriptor.management(), InstanceManagement::Systemd);
                let unit = configured
                    .systemd_unit()
                    .expect("validated systemd-managed instance has a unit");
                (descriptor.id().clone(), unit.as_str().to_owned())
            })
            .collect();
        Self {
            units,
            manager: Arc::new(ZbusSystemdManagerClient),
        }
    }

    #[cfg(test)]
    fn with_manager(
        units: impl IntoIterator<Item = (ServerInstanceId, String)>,
        manager: Arc<dyn SystemdManagerClient>,
    ) -> Self {
        Self {
            units: units.into_iter().collect(),
            manager,
        }
    }
}

impl LifecycleRuntime for SystemdLifecycleRuntime {
    fn dispatch<'a>(
        &'a self,
        instance_id: &'a ServerInstanceId,
        action: LifecycleAction,
    ) -> LifecycleRuntimeFuture<'a> {
        Box::pin(async move {
            let unit = self
                .units
                .get(instance_id)
                .ok_or(LifecycleRuntimeError::InstanceNotManaged)?;
            let job = self
                .manager
                .dispatch(unit, action)
                .await
                .map_err(LifecycleRuntimeError::from)?;
            SystemdJobReference::new(job).map_err(|_| LifecycleRuntimeError::InvalidJobReference)
        })
    }
}

const fn method_name(action: LifecycleAction) -> &'static str {
    match action {
        LifecycleAction::Start => "StartUnit",
        LifecycleAction::Stop => "StopUnit",
        LifecycleAction::Restart => "RestartUnit",
    }
}

#[derive(Debug)]
enum SystemdManagerError {
    Unavailable(String),
    Rejected(String),
}

impl SystemdManagerError {
    fn unavailable(error: zbus::Error) -> Self {
        Self::Unavailable(error.to_string())
    }

    fn rejected(error: zbus::Error) -> Self {
        Self::Rejected(error.to_string())
    }
}

impl From<SystemdManagerError> for LifecycleRuntimeError {
    fn from(error: SystemdManagerError) -> Self {
        match error {
            SystemdManagerError::Unavailable(message) => Self::Unavailable { message },
            SystemdManagerError::Rejected(message) => Self::Rejected { message },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Debug, Default)]
    struct RecordingManager {
        calls: Mutex<Vec<(String, LifecycleAction)>>,
        result: Mutex<Option<Result<String, SystemdManagerError>>>,
    }

    impl RecordingManager {
        fn succeeding() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                result: Mutex::new(Some(Ok("/org/freedesktop/systemd1/job/42".into()))),
            })
        }

        fn with_result(result: Result<String, SystemdManagerError>) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                result: Mutex::new(Some(result)),
            })
        }
    }

    impl SystemdManagerClient for RecordingManager {
        fn dispatch<'a>(&'a self, unit: &'a str, action: LifecycleAction) -> ManagerFuture<'a> {
            Box::pin(async move {
                self.calls.lock().unwrap().push((unit.to_owned(), action));
                self.result
                    .lock()
                    .unwrap()
                    .take()
                    .expect("test manager is called once")
            })
        }
    }

    fn test_runtime(manager: Arc<dyn SystemdManagerClient>) -> SystemdLifecycleRuntime {
        SystemdLifecycleRuntime::with_manager(
            [(
                ServerInstanceId::new("test").unwrap(),
                "lara-game@test.service".into(),
            )],
            manager,
        )
    }

    #[test]
    fn maps_actions_to_the_exact_systemd_manager_methods() {
        assert_eq!(method_name(LifecycleAction::Start), "StartUnit");
        assert_eq!(method_name(LifecycleAction::Stop), "StopUnit");
        assert_eq!(method_name(LifecycleAction::Restart), "RestartUnit");
    }

    #[tokio::test]
    async fn dispatches_only_the_allowlisted_unit_and_returns_the_job_path() {
        let manager = RecordingManager::succeeding();
        let runtime = test_runtime(manager.clone());

        let job = runtime
            .dispatch(
                &ServerInstanceId::new("test").unwrap(),
                LifecycleAction::Restart,
            )
            .await
            .unwrap();

        assert_eq!(job.as_str(), "/org/freedesktop/systemd1/job/42");
        assert_eq!(
            manager.calls.lock().unwrap().as_slice(),
            &[("lara-game@test.service".into(), LifecycleAction::Restart)]
        );
    }

    #[tokio::test]
    async fn rejects_external_or_unknown_instances_before_dbus() {
        let manager = RecordingManager::succeeding();
        let runtime = test_runtime(manager.clone());

        let result = runtime
            .dispatch(
                &ServerInstanceId::new("main").unwrap(),
                LifecycleAction::Stop,
            )
            .await;

        assert_eq!(result, Err(LifecycleRuntimeError::InstanceNotManaged));
        assert!(manager.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn preserves_safe_runtime_error_categories() {
        let runtime = test_runtime(RecordingManager::with_result(Err(
            SystemdManagerError::Rejected("polkit denied the request".into()),
        )));
        assert_eq!(
            runtime
                .dispatch(
                    &ServerInstanceId::new("test").unwrap(),
                    LifecycleAction::Start,
                )
                .await,
            Err(LifecycleRuntimeError::Rejected {
                message: "polkit denied the request".into()
            })
        );

        let runtime = test_runtime(RecordingManager::with_result(Ok(
            "not-an-object-path".into()
        )));
        assert_eq!(
            runtime
                .dispatch(
                    &ServerInstanceId::new("test").unwrap(),
                    LifecycleAction::Start,
                )
                .await,
            Err(LifecycleRuntimeError::InvalidJobReference)
        );
    }
}
