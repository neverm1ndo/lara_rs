use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use chrono::Utc;
use serde::Serialize;
use thiserror::Error;

use crate::{
    cli::{ConfigCommand, ConfigInitArgs, ConfigPathsArgs, ConfigValidateArgs, OutputFormat},
    server_instances::{
        application::registry::InstanceRegistry,
        infrastructure::config_registry::{ConfiguredInstanceRegistry, InstanceRegistryError},
    },
    shared::config::{AppConfig, ConfigError},
};

const PRODUCTION_TEMPLATE: &str = include_str!("assets/production.toml");
const ENVIRONMENT_TEMPLATE: &str = include_str!("assets/lara.env");

pub fn execute(command: ConfigCommand) -> Result<(), ConfigCliError> {
    match command {
        ConfigCommand::Init(args) => init(args),
        ConfigCommand::Validate(args) => validate(args),
        ConfigCommand::Paths(args) => paths(args),
    }
}

fn init(args: ConfigInitArgs) -> Result<(), ConfigCliError> {
    let layout = ConfigLayout::from_directory(args.config_dir);
    let overlay_environment_path = layout.overlay_file.to_string_lossy().replace('\\', "/");
    let environment_template =
        ENVIRONMENT_TEMPLATE.replace("/etc/lara/production.toml", &overlay_environment_path);
    let targets = [
        (
            &layout.overlay_file,
            PRODUCTION_TEMPLATE.as_bytes().to_vec(),
        ),
        (&layout.environment_file, environment_template.into_bytes()),
    ];
    let existing = targets
        .iter()
        .filter(|(path, _)| path.exists())
        .map(|(path, _)| (*path).clone())
        .collect::<Vec<_>>();

    let mut result = InitResult {
        dry_run: args.dry_run,
        config_directory: layout.config_directory.clone(),
        created: Vec::new(),
        replaced: Vec::new(),
        backups: Vec::new(),
    };
    if args.dry_run {
        for (path, _) in targets {
            if path.exists() {
                result.replaced.push(path.clone());
            } else {
                result.created.push(path.clone());
            }
        }
        return print_result(args.output, &result, human_init(&result));
    }
    if !existing.is_empty() && !args.yes {
        return Err(ConfigCliError::ConfirmationRequired(existing));
    }

    fs::create_dir_all(&layout.config_directory).map_err(|error| {
        io_error(
            "create configuration directory",
            &layout.config_directory,
            error,
        )
    })?;
    let lock_path = layout.config_directory.join(".lara-config.lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|error| io_error("open configuration lock", &lock_path, error))?;
    lock.lock()
        .map_err(|error| io_error("lock configuration directory", &lock_path, error))?;

    for (path, contents) in targets {
        if path.exists() {
            let backup = backup_path(path);
            fs::copy(path, &backup)
                .map_err(|error| io_error("back up configuration file", path, error))?;
            result.backups.push(backup);
            result.replaced.push(path.clone());
        } else {
            result.created.push(path.clone());
        }
        atomic_write(path, &contents, &layout.config_directory)?;
    }
    sync_directory(&layout.config_directory)?;
    File::unlock(&lock)
        .map_err(|error| io_error("unlock configuration directory", &lock_path, error))?;

    print_result(args.output, &result, human_init(&result))
}

fn validate(args: ConfigValidateArgs) -> Result<(), ConfigCliError> {
    let environment = dotenvy::from_path_iter(&args.environment_file)
        .and_then(|values| values.collect::<Result<Vec<_>, _>>())
        .map_err(|_| ConfigCliError::InvalidEnvironmentFile(args.environment_file.clone()))?;
    let config = AppConfig::load_explicit(&args.overlay_file, environment)?;
    let registry = ConfiguredInstanceRegistry::from_config(&config.game_server)?;
    let result = ValidationResult {
        valid: true,
        overlay_file: args.overlay_file,
        environment_file: args.environment_file,
        primary_instance: registry.primary().id().to_string(),
        instance_count: registry.list().len(),
    };
    let human = format!(
        "configuration is valid\nprimary instance: {}\nregistered instances: {}",
        result.primary_instance, result.instance_count
    );
    print_result(args.output, &result, human)
}

fn paths(args: ConfigPathsArgs) -> Result<(), ConfigCliError> {
    let layout = ConfigLayout::from_directory(args.config_dir);
    let human = format!(
        "configuration directory: {}\nenvironment file: {}\nproduction overlay: {}\ninstance environment directory: {}\nsystemd drop-ins: {}",
        layout.config_directory.display(),
        layout.environment_file.display(),
        layout.overlay_file.display(),
        layout.instance_environment_directory.display(),
        layout.systemd_drop_in_pattern.display(),
    );
    print_result(args.output, &layout, human)
}

pub(super) fn atomic_write(
    path: &Path,
    contents: &[u8],
    _owner_source: &Path,
) -> Result<(), ConfigCliError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ConfigCliError::InvalidPath(path.to_path_buf()))?;
    let temporary = path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));

    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o640)
            .open(&temporary)
    };
    #[cfg(not(unix))]
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary);
    let mut file =
        file.map_err(|error| io_error("create temporary configuration file", &temporary, error))?;
    file.write_all(contents)
        .map_err(|error| io_error("write temporary configuration file", &temporary, error))?;
    file.sync_all()
        .map_err(|error| io_error("sync temporary configuration file", &temporary, error))?;
    drop(file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, chown};
        let owner = fs::metadata(_owner_source).map_err(|error| {
            io_error("read configuration directory owner", _owner_source, error)
        })?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o640))
            .map_err(|error| io_error("set configuration permissions", &temporary, error))?;
        chown(&temporary, Some(owner.uid()), Some(owner.gid()))
            .map_err(|error| io_error("set configuration owner", &temporary, error))?;
    }

    fs::rename(&temporary, path)
        .map_err(|error| io_error("atomically install configuration file", path, error))?;
    Ok(())
}

pub(super) fn sync_directory(_path: &Path) -> Result<(), ConfigCliError> {
    #[cfg(unix)]
    File::open(_path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error("sync configuration directory", _path, error))?;
    Ok(())
}

pub(super) fn backup_path(path: &Path) -> PathBuf {
    let suffix = Utc::now().format("%Y%m%dT%H%M%S%.6fZ");
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!("{name}.bak-{suffix}"))
}

pub(super) fn print_result(
    output: OutputFormat,
    value: &impl Serialize,
    human: String,
) -> Result<(), ConfigCliError> {
    match output {
        OutputFormat::Human => println!("{human}"),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(value)?),
    }
    Ok(())
}

fn human_init(result: &InitResult) -> String {
    let mode = if result.dry_run {
        "planned"
    } else {
        "completed"
    };
    format!(
        "configuration initialization {mode}\ncreated: {}\nreplaced: {}\nbackups: {}\nservice was not started",
        result.created.len(),
        result.replaced.len(),
        result.backups.len()
    )
}

pub(super) fn io_error(
    action: &'static str,
    path: &Path,
    source: std::io::Error,
) -> ConfigCliError {
    ConfigCliError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigLayout {
    config_directory: PathBuf,
    environment_file: PathBuf,
    overlay_file: PathBuf,
    instance_environment_directory: PathBuf,
    systemd_drop_in_pattern: PathBuf,
}

impl ConfigLayout {
    fn from_directory(config_directory: PathBuf) -> Self {
        Self {
            environment_file: config_directory.join("lara.env"),
            overlay_file: config_directory.join("production.toml"),
            instance_environment_directory: config_directory.join("game-instances"),
            systemd_drop_in_pattern: PathBuf::from(
                "/etc/systemd/system/lara-game@<instance>.service.d/override.conf",
            ),
            config_directory,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InitResult {
    dry_run: bool,
    config_directory: PathBuf,
    created: Vec<PathBuf>,
    replaced: Vec<PathBuf>,
    backups: Vec<PathBuf>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidationResult {
    valid: bool,
    overlay_file: PathBuf,
    environment_file: PathBuf,
    primary_instance: String,
    instance_count: usize,
}

#[derive(Debug, Error)]
pub enum ConfigCliError {
    #[error("existing configuration requires --yes before replacement: {0:?}")]
    ConfirmationRequired(Vec<PathBuf>),
    #[error("invalid configuration path: {0}")]
    InvalidPath(PathBuf),
    #[error("environment file is missing or invalid: {0}")]
    InvalidEnvironmentFile(PathBuf),
    #[error("failed to {action} `{}`: {source}", path.display())]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Registry(#[from] InstanceRegistryError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temporary_directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lara-config-cli-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn dry_run_does_not_create_the_configuration_directory() {
        let directory = temporary_directory("dry-run");
        init(ConfigInitArgs {
            config_dir: directory.clone(),
            dry_run: true,
            yes: false,
            output: OutputFormat::Json,
        })
        .unwrap();

        assert!(!directory.exists());
    }

    #[test]
    fn init_creates_safe_templates_and_refuses_implicit_replacement() {
        let directory = temporary_directory("init");
        init(ConfigInitArgs {
            config_dir: directory.clone(),
            dry_run: false,
            yes: false,
            output: OutputFormat::Human,
        })
        .unwrap();

        let overlay = fs::read_to_string(directory.join("production.toml")).unwrap();
        let environment = fs::read_to_string(directory.join("lara.env")).unwrap();
        assert!(!overlay.contains("management"));
        assert!(!overlay.contains("dev-dm"));
        assert!(environment.contains(&format!(
            "LARA_CONFIG_FILE=\"{}\"",
            directory
                .join("production.toml")
                .to_string_lossy()
                .replace('\\', "/")
        )));
        init(ConfigInitArgs {
            config_dir: directory.clone(),
            dry_run: true,
            yes: false,
            output: OutputFormat::Json,
        })
        .unwrap();
        assert!(matches!(
            init(ConfigInitArgs {
                config_dir: directory.clone(),
                dry_run: false,
                yes: false,
                output: OutputFormat::Human,
            }),
            Err(ConfigCliError::ConfirmationRequired(_))
        ));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn validate_uses_explicit_files_and_the_daemon_registry_rules() {
        let directory = temporary_directory("validate");
        fs::create_dir_all(&directory).unwrap();
        let overlay = directory.join("production.toml");
        let environment = directory.join("lara.env");
        fs::write(&overlay, PRODUCTION_TEMPLATE).unwrap();
        fs::write(
            &environment,
            format!(
                "LARA_MYSQL__URL=mysql://localhost/lara\nLARA_MONGODB__URI=mongodb://localhost:27017\nLARA_JWT__SECRET=environment-secret-with-32-bytes!\nLARA_MFA__ENCRYPTION_KEY={}\n",
                "11".repeat(32)
            ),
        )
        .unwrap();

        validate(ConfigValidateArgs {
            overlay_file: overlay,
            environment_file: environment,
            output: OutputFormat::Json,
        })
        .unwrap();

        fs::remove_dir_all(directory).unwrap();
    }
}
