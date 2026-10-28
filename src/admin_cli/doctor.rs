use std::{path::Path, time::Duration};

use mongodb::{Client, bson::doc};
use sea_orm::{ConnectionTrait, Database};
use serde::Serialize;
use thiserror::Error;

use super::{
    config::{ConfigCliError, print_result},
    instance::{
        InstanceCliError, VerificationStatus, collect_instance_verification,
        human_verification_report,
    },
};
use crate::{
    cli::{DoctorArgs, InstanceConfigArgs, InstanceVerifyArgs},
    server_instances::{
        application::registry::InstanceRegistry,
        domain::{InstanceCapability, InstanceKind, InstanceManagement},
        infrastructure::config_registry::ConfiguredInstanceRegistry,
    },
    shared::config::AppConfig,
};

const POLKIT_RULE: &str = include_str!("../../deploy/polkit/49-lara-rs.rules");

pub async fn execute(args: DoctorArgs) -> Result<(), DoctorError> {
    let environment = match read_environment(&args.environment_file) {
        Ok(environment) => environment,
        Err(error) => {
            return finish(
                args.output,
                vec![DoctorCheck::failed(
                    "configuration.environment",
                    "environment file could not be read",
                    Some(error),
                )],
            );
        }
    };
    let config = match AppConfig::load_explicit(&args.overlay_file, environment) {
        Ok(config) => config,
        Err(error) => {
            return finish(
                args.output,
                vec![DoctorCheck::failed(
                    "configuration.startup",
                    "configuration failed daemon startup validation",
                    Some(error.to_string()),
                )],
            );
        }
    };
    let registry = match ConfiguredInstanceRegistry::from_config(&config.game_server) {
        Ok(registry) => registry,
        Err(error) => {
            return finish(
                args.output,
                vec![DoctorCheck::failed(
                    "configuration.registry",
                    "instance registry is invalid",
                    Some(error.to_string()),
                )],
            );
        }
    };

    let mut checks = vec![
        DoctorCheck::passed(
            "configuration.startup",
            "configuration passes daemon startup validation",
            Some(args.overlay_file.display().to_string()),
        ),
        DoctorCheck::passed(
            "configuration.registry",
            "instance registry is valid",
            Some(format!("{} instances", registry.list().len())),
        ),
        check_polkit_rule(&args.polkit_rule),
        check_directory(
            "storage.backups",
            "backup storage directory exists",
            &config.backups.storage.directory,
        ),
    ];
    for instance in registry.list() {
        let configured = registry
            .configured(instance.id())
            .expect("listed instance has configured metadata");
        checks.push(check_directory(
            format!("instance.{}.storage", instance.id()),
            format!("storage root for `{}` exists", instance.id()),
            configured.storage_root(),
        ));
        if instance
            .capabilities()
            .contains(InstanceCapability::Configuration)
        {
            checks.push(check_group_access(
                instance.id().as_str(),
                configured.storage_root(),
            ));
        }
    }

    let timeout = Duration::from_secs(args.database_timeout_seconds);
    let (mysql, mongo) = tokio::join!(
        check_mysql(config.mysql.url.expose_secret(), timeout),
        check_mongo(
            config.mongodb.uri.expose_secret(),
            &config.mongodb.database,
            timeout
        )
    );
    checks.push(mysql);
    checks.push(mongo);

    let selected = registry
        .list()
        .into_iter()
        .filter(|instance| {
            args.instance
                .as_deref()
                .is_none_or(|selected| instance.id().as_str() == selected)
        })
        .collect::<Vec<_>>();
    if let Some(selected_id) = &args.instance
        && selected.is_empty()
    {
        checks.push(DoctorCheck::failed(
            "instance.selection",
            "selected instance is not registered",
            Some(selected_id.clone()),
        ));
    }

    let mut process_targets = Vec::new();
    for instance in selected {
        if instance.kind() != InstanceKind::Auxiliary
            || instance.management() != InstanceManagement::Systemd
        {
            checks.push(DoctorCheck::warning(
                format!("instance.{}.readiness", instance.id()),
                "external primary diagnostics require the future UDS readiness adapter",
                None,
            ));
            continue;
        }
        let configured = registry
            .configured(instance.id())
            .expect("listed instance has configured metadata");
        let executable = configured.storage_root().join("omp-server");
        let unit = configured
            .systemd_unit()
            .expect("systemd-managed instance has a unit")
            .as_str()
            .to_owned();
        process_targets.push((instance.id().to_string(), unit, executable));
        let verify_args = InstanceVerifyArgs {
            id: instance.id().to_string(),
            executable: None,
            user: args.user.clone(),
            group: args.group.clone(),
            systemd_directory: args.systemd_directory.clone(),
            instance_environment_directory: args.instance_environment_directory.clone(),
            config: InstanceConfigArgs {
                overlay_file: args.overlay_file.clone(),
                environment_file: args.environment_file.clone(),
                output: args.output,
            },
        };
        match collect_instance_verification(verify_args).await {
            Ok(report) => {
                let report_summary = human_verification_report(&report);
                checks.push(if report.valid {
                    DoctorCheck::passed(
                        format!("instance.{}.verify", report.instance_id),
                        "instance verification passed",
                        Some(report_summary),
                    )
                } else {
                    DoctorCheck::failed(
                        format!("instance.{}.verify", report.instance_id),
                        "instance verification found blocking drift",
                        Some(report_summary),
                    )
                });
                for check in report.checks {
                    if check.status == VerificationStatus::Warning {
                        checks.push(DoctorCheck::warning(
                            format!("instance.{}.{}", report.instance_id, check.id),
                            check.summary,
                            check.detail,
                        ));
                    }
                }
            }
            Err(error) => checks.push(DoctorCheck::failed(
                format!("instance.{}.verify", instance.id()),
                "instance verification could not run",
                Some(error.to_string()),
            )),
        }
    }
    checks.push(check_process_ownership(&process_targets));
    checks.push(DoctorCheck::warning(
        "polkit.effective",
        "static least-privilege rule is checked, but authorization for the lara process requires a Linux integration test",
        None,
    ));

    finish(args.output, checks)
}

fn read_environment(path: &Path) -> Result<Vec<(String, String)>, String> {
    dotenvy::from_path_iter(path)
        .and_then(|values| values.collect::<Result<Vec<_>, _>>())
        .map_err(|_| format!("{} is missing or invalid", path.display()))
}

async fn check_mysql(url: &str, timeout: Duration) -> DoctorCheck {
    let result = tokio::time::timeout(timeout, async {
        let connection = Database::connect(url).await?;
        connection.execute_unprepared("SELECT 1").await?;
        connection.close().await
    })
    .await;
    match result {
        Ok(Ok(())) => DoctorCheck::passed("database.mysql", "MySQL ping succeeded", None),
        Ok(Err(_)) => DoctorCheck::failed(
            "database.mysql",
            "MySQL ping failed",
            Some("connection details are redacted".into()),
        ),
        Err(_) => DoctorCheck::failed(
            "database.mysql",
            "MySQL ping timed out",
            Some(format!("timeout={}s", timeout.as_secs())),
        ),
    }
}

async fn check_mongo(uri: &str, database: &str, timeout: Duration) -> DoctorCheck {
    let result = tokio::time::timeout(timeout, async {
        let client = Client::with_uri_str(uri).await?;
        client
            .database(database)
            .run_command(doc! { "ping": 1 })
            .await?;
        Ok::<(), mongodb::error::Error>(())
    })
    .await;
    match result {
        Ok(Ok(())) => DoctorCheck::passed("database.mongodb", "MongoDB ping succeeded", None),
        Ok(Err(_)) => DoctorCheck::failed(
            "database.mongodb",
            "MongoDB ping failed",
            Some("connection details are redacted".into()),
        ),
        Err(_) => DoctorCheck::failed(
            "database.mongodb",
            "MongoDB ping timed out",
            Some(format!("timeout={}s", timeout.as_secs())),
        ),
    }
}

fn check_polkit_rule(path: &Path) -> DoctorCheck {
    match std::fs::read_to_string(path) {
        Ok(contents) if contents == POLKIT_RULE => DoctorCheck::passed(
            "polkit.rule",
            "installed polkit rule matches the packaged least-privilege policy",
            Some(path.display().to_string()),
        ),
        Ok(_) => DoctorCheck::failed(
            "polkit.rule",
            "installed polkit rule differs from the packaged policy",
            Some(path.display().to_string()),
        ),
        Err(error) => DoctorCheck::failed(
            "polkit.rule",
            "packaged polkit rule is not readable",
            Some(format!("{}: {error}", path.display())),
        ),
    }
}

fn check_directory(id: impl Into<String>, summary: impl Into<String>, path: &Path) -> DoctorCheck {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            DoctorCheck::passed(id, summary, Some(path.display().to_string()))
        }
        Ok(_) => DoctorCheck::failed(
            id,
            summary,
            Some(format!("{} is not a real directory", path.display())),
        ),
        Err(error) => {
            DoctorCheck::failed(id, summary, Some(format!("{}: {error}", path.display())))
        }
    }
}

fn check_group_access(instance_id: &str, path: &Path) -> DoctorCheck {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.permissions().mode() & 0o070 == 0o070 => DoctorCheck::passed(
                format!("instance.{instance_id}.configuration-access"),
                "classic group bits allow configuration traversal and writes",
                Some(path.display().to_string()),
            ),
            Ok(_) => DoctorCheck::warning(
                format!("instance.{instance_id}.configuration-access"),
                "classic group bits do not prove Lara access; verify any POSIX ACL explicitly",
                Some(path.display().to_string()),
            ),
            Err(error) => DoctorCheck::failed(
                format!("instance.{instance_id}.configuration-access"),
                "configuration-capable storage permissions are unavailable",
                Some(error.to_string()),
            ),
        }
    }
    #[cfg(not(unix))]
    DoctorCheck::warning(
        format!("instance.{instance_id}.configuration-access"),
        "Unix group and ACL checks are unavailable on this platform",
        Some(path.display().to_string()),
    )
}

fn check_process_ownership(targets: &[(String, String, std::path::PathBuf)]) -> DoctorCheck {
    #[cfg(target_os = "linux")]
    {
        let mut rogue = Vec::new();
        for (instance_id, unit, executable) in targets {
            let Ok(expected_executable) = std::fs::canonicalize(executable) else {
                continue;
            };
            let Ok(processes) = std::fs::read_dir("/proc") else {
                return DoctorCheck::failed(
                    "process.cgroup-ownership",
                    "process table could not be inspected",
                    None,
                );
            };
            for process in processes.flatten() {
                let name = process.file_name();
                let Some(pid) = name.to_str().filter(|value| {
                    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                }) else {
                    continue;
                };
                let process_root = process.path();
                let Ok(actual_executable) = std::fs::read_link(process_root.join("exe")) else {
                    continue;
                };
                if actual_executable != expected_executable {
                    continue;
                }
                let cgroup =
                    std::fs::read_to_string(process_root.join("cgroup")).unwrap_or_default();
                if !cgroup.contains(unit) {
                    rogue.push(format!("{instance_id}:pid={pid}"));
                }
            }
        }
        if rogue.is_empty() {
            DoctorCheck::passed(
                "process.cgroup-ownership",
                "no registered executable runs outside its expected systemd cgroup",
                None,
            )
        } else {
            DoctorCheck::failed(
                "process.cgroup-ownership",
                "a registered executable is running outside its expected systemd cgroup",
                Some(rogue.join(", ")),
            )
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = targets;
        DoctorCheck::warning(
            "process.cgroup-ownership",
            "Linux /proc cgroup inspection is unavailable on this platform",
            None,
        )
    }
}

fn finish(output: crate::cli::OutputFormat, checks: Vec<DoctorCheck>) -> Result<(), DoctorError> {
    let failures = checks
        .iter()
        .filter(|check| check.status == DoctorStatus::Failed)
        .count();
    let warnings = checks
        .iter()
        .filter(|check| check.status == DoctorStatus::Warning)
        .count();
    let report = DoctorReport {
        healthy: failures == 0,
        failures,
        warnings,
        checks,
    };
    let human = report
        .checks
        .iter()
        .map(|check| {
            let detail = check
                .detail
                .as_deref()
                .map(|detail| format!(": {detail}"))
                .unwrap_or_default();
            format!(
                "[{}] {} — {}{}",
                check.status.label(),
                check.id,
                check.summary,
                detail
            )
        })
        .chain(std::iter::once(format!(
            "result: {} ({} failures, {} warnings)",
            if report.healthy {
                "healthy"
            } else {
                "unhealthy"
            },
            failures,
            warnings
        )))
        .collect::<Vec<_>>()
        .join("\n");
    print_result(output, &report, human)?;
    if failures == 0 {
        Ok(())
    } else {
        Err(DoctorError::Unhealthy { failures })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DoctorReport {
    healthy: bool,
    failures: usize,
    warnings: usize,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DoctorCheck {
    id: String,
    status: DoctorStatus,
    summary: String,
    detail: Option<String>,
}

impl DoctorCheck {
    fn passed(id: impl Into<String>, summary: impl Into<String>, detail: Option<String>) -> Self {
        Self::new(id, DoctorStatus::Passed, summary, detail)
    }

    fn warning(id: impl Into<String>, summary: impl Into<String>, detail: Option<String>) -> Self {
        Self::new(id, DoctorStatus::Warning, summary, detail)
    }

    fn failed(id: impl Into<String>, summary: impl Into<String>, detail: Option<String>) -> Self {
        Self::new(id, DoctorStatus::Failed, summary, detail)
    }

    fn new(
        id: impl Into<String>,
        status: DoctorStatus,
        summary: impl Into<String>,
        detail: Option<String>,
    ) -> Self {
        Self {
            id: id.into(),
            status,
            summary: summary.into(),
            detail,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DoctorStatus {
    Passed,
    Warning,
    Failed,
}

impl DoctorStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::Passed => "PASS",
            Self::Warning => "WARN",
            Self::Failed => "FAIL",
        }
    }
}

#[derive(Debug, Error)]
pub enum DoctorError {
    #[error("doctor found {failures} blocking problem(s)")]
    Unhealthy { failures: usize },
    #[error(transparent)]
    ConfigCli(#[from] ConfigCliError),
    #[error(transparent)]
    Instance(#[from] InstanceCliError),
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn packaged_polkit_rule_is_narrowly_scoped() {
        assert!(POLKIT_RULE.contains("subject.user === \"lara\""));
        assert!(POLKIT_RULE.contains("org.freedesktop.systemd1.manage-units"));
        assert!(POLKIT_RULE.contains("lara-game@"));
        for verb in ["start", "stop", "restart"] {
            assert!(POLKIT_RULE.contains(&format!("\"{verb}\"")));
        }
        for forbidden in ["enable", "disable", "kill", "reload-or-restart"] {
            assert!(!POLKIT_RULE.contains(&format!("\"{forbidden}\"")));
        }
    }

    #[test]
    fn polkit_check_detects_drift_without_executing_an_action() {
        let path = std::env::temp_dir().join(format!(
            "lara-polkit-{}-{}.rules",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, POLKIT_RULE).unwrap();
        assert_eq!(check_polkit_rule(&path).status, DoctorStatus::Passed);
        std::fs::write(
            &path,
            "polkit.addRule(function() { return polkit.Result.YES; });",
        )
        .unwrap();
        assert_eq!(check_polkit_rule(&path).status, DoctorStatus::Failed);
        std::fs::remove_file(path).unwrap();
    }
}
