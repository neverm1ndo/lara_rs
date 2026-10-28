use std::time::Duration;

use thiserror::Error;
use zbus::{Connection, Proxy, zvariant::OwnedObjectPath};

const SYSTEMD_DESTINATION: &str = "org.freedesktop.systemd1";
const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const SYSTEMD_UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SYSTEMD_SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";
const INSPECTION_TIMEOUT: Duration = Duration::from_secs(5);

type SystemdExecEntry = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveSystemdUnit {
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub fragment_path: String,
    pub drop_in_paths: Vec<String>,
    pub user: String,
    pub group: String,
    pub working_directory: String,
    pub exec_start: Vec<SystemdExecCommand>,
    pub protect_home: String,
    pub read_write_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdExecCommand {
    pub path: String,
    pub arguments: Vec<String>,
}

/// Reads the effective unit definition from PID 1. `LoadUnit` only asks the
/// manager to materialize metadata for inspection; it does not queue a start,
/// stop or restart job.
pub async fn inspect_systemd_unit(
    unit_name: &str,
) -> Result<EffectiveSystemdUnit, SystemdInspectionError> {
    tokio::time::timeout(INSPECTION_TIMEOUT, inspect(unit_name))
        .await
        .map_err(|_| SystemdInspectionError::TimedOut)?
}

async fn inspect(unit_name: &str) -> Result<EffectiveSystemdUnit, SystemdInspectionError> {
    let connection = Connection::system().await?;
    let manager = Proxy::new(
        &connection,
        SYSTEMD_DESTINATION,
        SYSTEMD_MANAGER_PATH,
        SYSTEMD_MANAGER_INTERFACE,
    )
    .await?;
    let path: OwnedObjectPath = manager.call("LoadUnit", &(unit_name,)).await?;
    let unit = Proxy::new(
        &connection,
        SYSTEMD_DESTINATION,
        path.as_str(),
        SYSTEMD_UNIT_INTERFACE,
    )
    .await?;
    let service = Proxy::new(
        &connection,
        SYSTEMD_DESTINATION,
        path.as_str(),
        SYSTEMD_SERVICE_INTERFACE,
    )
    .await?;

    let (
        load_state,
        active_state,
        sub_state,
        fragment_path,
        drop_in_paths,
        user,
        group,
        working_directory,
        exec_start,
        protect_home,
        read_write_paths,
    ) = tokio::try_join!(
        unit.get_property::<String>("LoadState"),
        unit.get_property::<String>("ActiveState"),
        unit.get_property::<String>("SubState"),
        unit.get_property::<String>("FragmentPath"),
        unit.get_property::<Vec<String>>("DropInPaths"),
        service.get_property::<String>("User"),
        service.get_property::<String>("Group"),
        service.get_property::<String>("WorkingDirectory"),
        service.get_property::<Vec<SystemdExecEntry>>("ExecStart"),
        service.get_property::<String>("ProtectHome"),
        service.get_property::<Vec<String>>("ReadWritePaths"),
    )?;

    Ok(EffectiveSystemdUnit {
        load_state,
        active_state,
        sub_state,
        fragment_path,
        drop_in_paths,
        user,
        group,
        working_directory,
        exec_start: exec_start
            .into_iter()
            .map(|entry| SystemdExecCommand {
                path: entry.0,
                arguments: entry.1,
            })
            .collect(),
        protect_home,
        read_write_paths,
    })
}

#[derive(Debug, Error)]
pub enum SystemdInspectionError {
    #[error("systemd D-Bus inspection timed out")]
    TimedOut,
    #[error("systemd D-Bus inspection failed: {0}")]
    Dbus(#[from] zbus::Error),
}
