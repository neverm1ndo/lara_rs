use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

use serde::Serialize;
use thiserror::Error;
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, Value, value};

use super::config::{
    ConfigCliError, atomic_write, atomic_write_with_mode, backup_path, io_error, print_result,
    sync_directory,
};
use crate::{
    cli::{
        InstanceAddArgs, InstanceCapabilityArg, InstanceCommand, InstanceConfigArgs,
        InstanceEditArgs, InstanceEnvironmentArg, InstanceListArgs, InstanceRemoveArgs,
        InstanceRenderSystemdArgs, OutputFormat,
    },
    server_instances::{
        application::registry::InstanceRegistry,
        domain::{
            InstanceCapability, InstanceEnvironment, InstanceKind, InstanceManagement,
            InstanceReadiness, ServerInstance,
        },
        infrastructure::{
            config_registry::{ConfiguredInstanceRegistry, InstanceRegistryError},
            systemd_runtime::{SystemdReloadError, reload_systemd_manager},
        },
    },
    shared::config::{AppConfig, ConfigError},
};

pub async fn execute(command: InstanceCommand) -> Result<(), InstanceCliError> {
    match command {
        InstanceCommand::List(args) => list(args),
        InstanceCommand::Add(args) => add(args),
        InstanceCommand::Edit(args) => edit(args),
        InstanceCommand::Remove(args) => remove(args),
        InstanceCommand::RenderSystemd(args) => render_systemd(args).await,
    }
}

fn list(args: InstanceListArgs) -> Result<(), InstanceCliError> {
    let loaded = LoadedRegistry::read(&args.config)?;
    let instances = loaded
        .registry
        .list()
        .iter()
        .map(|instance| instance_view(&loaded.registry, instance))
        .collect::<Result<Vec<_>, _>>()?;
    let result = InstanceListResult {
        primary_instance: loaded.registry.primary().id().to_string(),
        instances,
    };
    let human = result
        .instances
        .iter()
        .map(|instance| {
            format!(
                "{}\t{}\t{}\t{}\t{}",
                instance.id,
                instance.kind,
                instance.management,
                instance.display_name,
                instance.storage_root.display()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    print_result(args.config.output, &result, human)?;
    Ok(())
}

fn add(args: InstanceAddArgs) -> Result<(), InstanceCliError> {
    let loaded = LoadedRegistry::read(&args.config)?;
    if loaded
        .registry
        .list()
        .iter()
        .any(|item| item.id().as_str() == args.id)
    {
        return Err(InstanceCliError::AlreadyExists(args.id));
    }

    let mut document = loaded.document.clone();
    materialize_primary(&mut document, &loaded.registry)?;
    instances_mut(&mut document)?.push(auxiliary_table(&args));
    let candidate = document.to_string();
    let registry = validate_candidate(&candidate, &loaded.environment)?;
    let instance = registry
        .list()
        .into_iter()
        .find(|instance| instance.id().as_str() == args.id)
        .ok_or_else(|| InstanceCliError::NotFound(args.id.clone()))?;
    let result = MutationResult {
        action: "add",
        instance: instance_view(&registry, &instance)?,
        overlay_file: args.config.overlay_file.clone(),
        backup: None,
        dry_run: args.dry_run,
        storage_files_changed: false,
    };
    finish_mutation(args.config.output, &loaded, candidate, result)
}

fn edit(args: InstanceEditArgs) -> Result<(), InstanceCliError> {
    if args.display_name.is_none()
        && args.environment.is_none()
        && args.storage_root.is_none()
        && args.capabilities.is_empty()
        && args.sort_order.is_none()
        && args.systemd_unit.is_none()
    {
        return Err(InstanceCliError::NoChanges);
    }
    let loaded = LoadedRegistry::read(&args.config)?;
    reject_primary(&loaded.registry, &args.id)?;
    let mut document = loaded.document.clone();
    let table = find_instance_mut(&mut document, &args.id)?;
    if let Some(display_name) = &args.display_name {
        table["display_name"] = value(display_name);
    }
    if let Some(environment) = args.environment {
        table["environment"] = value(environment_name(environment));
    }
    if let Some(storage_root) = &args.storage_root {
        table["storage_root"] = value(path_value(storage_root));
    }
    if !args.capabilities.is_empty() {
        table["capabilities"] = Item::Value(Value::Array(capability_array(&args.capabilities)));
    }
    if let Some(sort_order) = args.sort_order {
        table["sort_order"] = value(i64::from(sort_order));
    }
    if let Some(systemd_unit) = &args.systemd_unit {
        table["systemd_unit"] = value(systemd_unit);
    }

    let candidate = document.to_string();
    let registry = validate_candidate(&candidate, &loaded.environment)?;
    let instance = registry
        .list()
        .into_iter()
        .find(|instance| instance.id().as_str() == args.id)
        .ok_or_else(|| InstanceCliError::NotFound(args.id.clone()))?;
    let result = MutationResult {
        action: "edit",
        instance: instance_view(&registry, &instance)?,
        overlay_file: args.config.overlay_file.clone(),
        backup: None,
        dry_run: args.dry_run,
        storage_files_changed: false,
    };
    finish_mutation(args.config.output, &loaded, candidate, result)
}

fn remove(args: InstanceRemoveArgs) -> Result<(), InstanceCliError> {
    let loaded = LoadedRegistry::read(&args.config)?;
    reject_primary(&loaded.registry, &args.id)?;
    let removed_instance = loaded
        .registry
        .list()
        .into_iter()
        .find(|instance| instance.id().as_str() == args.id)
        .ok_or_else(|| InstanceCliError::NotFound(args.id.clone()))?;
    let removed_view = instance_view(&loaded.registry, &removed_instance)?;
    if !args.dry_run && !args.yes {
        return Err(InstanceCliError::ConfirmationRequired(args.id));
    }
    let mut document = loaded.document.clone();
    let instances = instances_mut(&mut document)?;
    let index = instances
        .iter()
        .position(|table| table_id(table) == Some(args.id.as_str()))
        .ok_or_else(|| InstanceCliError::NotFound(args.id.clone()))?;
    instances.remove(index);
    let candidate = document.to_string();
    validate_candidate(&candidate, &loaded.environment)?;
    let result = MutationResult {
        action: "remove",
        instance: removed_view,
        overlay_file: args.config.overlay_file.clone(),
        backup: None,
        dry_run: args.dry_run,
        storage_files_changed: false,
    };
    finish_mutation(args.config.output, &loaded, candidate, result)
}

fn finish_mutation(
    output: OutputFormat,
    loaded: &LoadedRegistry,
    candidate: String,
    mut result: MutationResult,
) -> Result<(), InstanceCliError> {
    if !result.dry_run {
        result.backup = Some(commit_overlay(
            &loaded.overlay_file,
            &loaded.source,
            candidate.as_bytes(),
        )?);
    }
    let mode = if result.dry_run {
        "planned"
    } else {
        "completed"
    };
    let human = format!(
        "instance {} {mode}: {}\noverlay: {}\nstorage files changed: no",
        result.action,
        result.instance.id,
        result.overlay_file.display()
    );
    print_result(output, &result, human)?;
    Ok(())
}

async fn render_systemd(args: InstanceRenderSystemdArgs) -> Result<(), InstanceCliError> {
    let loaded = LoadedRegistry::read(&args.config)?;
    let descriptor = loaded
        .registry
        .list()
        .into_iter()
        .find(|instance| instance.id().as_str() == args.id)
        .ok_or_else(|| InstanceCliError::NotFound(args.id.clone()))?;
    if descriptor.kind() != InstanceKind::Auxiliary
        || descriptor.management() != InstanceManagement::Systemd
    {
        return Err(InstanceCliError::NotSystemdManaged(args.id));
    }
    let configured = loaded
        .registry
        .configured(descriptor.id())
        .ok_or_else(|| InstanceCliError::NotFound(descriptor.id().to_string()))?;
    let systemd_unit = configured
        .systemd_unit()
        .ok_or_else(|| InstanceCliError::NotSystemdManaged(descriptor.id().to_string()))?
        .as_str()
        .to_owned();
    let storage_root = configured.storage_root().to_path_buf();
    let executable = args
        .executable
        .clone()
        .unwrap_or_else(|| storage_root.join("omp-server"));

    validate_render_paths(
        &storage_root,
        &executable,
        &args.systemd_directory,
        &args.instance_environment_directory,
    )?;
    validate_identity(&args.user, IdentityKind::User)?;
    validate_identity(&args.group, IdentityKind::Group)?;
    validate_executable(&storage_root, &executable)?;

    let drop_in_directory = args.systemd_directory.join(format!("{systemd_unit}.d"));
    let drop_in_file = drop_in_directory.join("override.conf");
    let environment_file = args
        .instance_environment_directory
        .join(format!("{}.env", descriptor.id()));
    let needs_home_access = path_requires_home_access(&storage_root);
    let contents = render_drop_in(
        &storage_root,
        &executable,
        &environment_file,
        &args.user,
        &args.group,
        needs_home_access,
    )?;
    let existing = match fs::read(&drop_in_file) {
        Ok(contents) => Some(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(io_error("read existing systemd drop-in", &drop_in_file, error).into());
        }
    };
    let changed = existing.as_deref() != Some(contents.as_bytes());
    let replacing = existing.is_some() && changed;
    if replacing && !args.dry_run && !args.yes {
        return Err(InstanceCliError::DropInConfirmationRequired(drop_in_file));
    }

    let mut result = SystemdRenderResult {
        instance_id: descriptor.id().to_string(),
        systemd_unit,
        storage_root,
        executable,
        user: args.user,
        group: args.group,
        drop_in_file,
        environment_file,
        protect_home: !needs_home_access,
        dry_run: args.dry_run,
        changed,
        backup: None,
        daemon_reloaded: false,
        generated_contents: contents.clone(),
        acl_guidance: vec![
            "Grant the game-server account only the access required by this instance root."
                .into(),
            "If configuration is enabled, ensure the lara-game group can read and write the intended files."
                .into(),
            "Do not use recursive chown until the exact storage root has been reviewed.".into(),
        ],
    };

    if changed && !args.dry_run {
        result.backup = install_drop_in(
            &loaded.overlay_file,
            &loaded.source,
            &drop_in_directory,
            &result.drop_in_file,
            existing.as_deref(),
            contents.as_bytes(),
        )?;
        if args.reload {
            reload_systemd_manager().await.map_err(|source| {
                InstanceCliError::ReloadAfterInstall {
                    path: result.drop_in_file.clone(),
                    source,
                }
            })?;
            result.daemon_reloaded = true;
        }
    }

    let mode = if args.dry_run {
        "planned"
    } else if changed {
        "installed"
    } else {
        "already current"
    };
    let mut human = format!(
        "systemd drop-in {mode}: {}\nunit: {}\nworking directory: {}\nexecutable: {}\nProtectHome: {}\ndaemon reloaded: {}\ninstance was not enabled or started",
        result.drop_in_file.display(),
        result.systemd_unit,
        result.storage_root.display(),
        result.executable.display(),
        if result.protect_home { "yes" } else { "no" },
        result.daemon_reloaded,
    );
    if args.dry_run {
        human.push_str("\n\ngenerated drop-in:\n");
        human.push_str(&result.generated_contents);
    }
    print_result(args.config.output, &result, human)?;
    Ok(())
}

fn validate_render_paths(
    storage_root: &Path,
    executable: &Path,
    systemd_directory: &Path,
    environment_directory: &Path,
) -> Result<(), InstanceCliError> {
    for (name, path) in [
        ("storage root", storage_root),
        ("executable", executable),
        ("systemd directory", systemd_directory),
        ("instance environment directory", environment_directory),
    ] {
        if !path.is_absolute() {
            return Err(InstanceCliError::PathMustBeAbsolute {
                name,
                path: path.to_path_buf(),
            });
        }
        let text = path.to_string_lossy();
        if text.contains(['\n', '\r', '\0', '%', '$']) {
            return Err(InstanceCliError::UnsafeSystemdPath(path.to_path_buf()));
        }
    }
    if !executable.starts_with(storage_root) {
        return Err(InstanceCliError::ExecutableOutsideStorageRoot {
            executable: executable.to_path_buf(),
            storage_root: storage_root.to_path_buf(),
        });
    }
    Ok(())
}

fn validate_executable(storage_root: &Path, executable: &Path) -> Result<(), InstanceCliError> {
    let root_metadata = fs::symlink_metadata(storage_root)
        .map_err(|error| io_error("inspect instance storage root", storage_root, error))?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(InstanceCliError::InvalidStorageRoot(
            storage_root.to_path_buf(),
        ));
    }
    let executable_metadata = fs::metadata(executable)
        .map_err(|error| io_error("inspect game-server executable", executable, error))?;
    if !executable_metadata.is_file() {
        return Err(InstanceCliError::InvalidExecutable(
            executable.to_path_buf(),
        ));
    }
    let canonical_root = fs::canonicalize(storage_root)
        .map_err(|error| io_error("canonicalize instance storage root", storage_root, error))?;
    let canonical_executable = fs::canonicalize(executable)
        .map_err(|error| io_error("canonicalize game-server executable", executable, error))?;
    if !canonical_executable.starts_with(&canonical_root) {
        return Err(InstanceCliError::ExecutableOutsideStorageRoot {
            executable: canonical_executable,
            storage_root: canonical_root,
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if executable_metadata.permissions().mode() & 0o111 == 0 {
            return Err(InstanceCliError::ExecutablePermission(
                executable.to_path_buf(),
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum IdentityKind {
    User,
    Group,
}

fn validate_identity(name: &str, kind: IdentityKind) -> Result<(), InstanceCliError> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    if !valid {
        return Err(InstanceCliError::InvalidUnixIdentity(name.to_owned()));
    }
    #[cfg(unix)]
    {
        let database = match kind {
            IdentityKind::User => Path::new("/etc/passwd"),
            IdentityKind::Group => Path::new("/etc/group"),
        };
        let contents = fs::read_to_string(database)
            .map_err(|error| io_error("read Unix identity database", database, error))?;
        if !contents
            .lines()
            .any(|line| line.split_once(':').is_some_and(|(entry, _)| entry == name))
        {
            return Err(InstanceCliError::UnixIdentityNotFound(name.to_owned()));
        }
    }
    #[cfg(not(unix))]
    let _ = kind;
    Ok(())
}

fn render_drop_in(
    storage_root: &Path,
    executable: &Path,
    environment_file: &Path,
    user: &str,
    group: &str,
    under_home: bool,
) -> Result<String, InstanceCliError> {
    let root = quote_systemd_path(storage_root)?;
    let executable = quote_systemd_path(executable)?;
    let environment = quote_systemd_path(environment_file)?;
    Ok(format!(
        "# Generated by `lara instance render-systemd`; local edits require explicit reconciliation.\n[Service]\nUser={user}\nGroup={group}\nWorkingDirectory={root}\nExecStart=\nExecStart={executable}\nEnvironmentFile=\nEnvironmentFile=-{environment}\nProtectHome={}\nReadWritePaths=\nReadWritePaths={root}\n",
        if under_home { "no" } else { "yes" }
    ))
}

fn quote_systemd_path(path: &Path) -> Result<String, InstanceCliError> {
    let text = path
        .to_str()
        .ok_or_else(|| InstanceCliError::NonUtf8SystemdPath(path.to_path_buf()))?;
    if text.contains(['\n', '\r', '\0', '%', '$']) {
        return Err(InstanceCliError::UnsafeSystemdPath(path.to_path_buf()));
    }
    Ok(format!(
        "\"{}\"",
        text.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn path_requires_home_access(path: &Path) -> bool {
    let mut components = path.components();
    if !matches!(components.next(), Some(std::path::Component::RootDir)) {
        return false;
    }
    match components.next().map(|component| component.as_os_str()) {
        Some(component) if component == "home" || component == "root" => true,
        Some(component) if component == "run" => components
            .next()
            .is_some_and(|component| component.as_os_str() == "user"),
        _ => false,
    }
}

fn install_drop_in(
    overlay_file: &Path,
    expected_overlay: &str,
    drop_in_directory: &Path,
    drop_in_file: &Path,
    expected_existing: Option<&[u8]>,
    contents: &[u8],
) -> Result<Option<PathBuf>, InstanceCliError> {
    let config_directory = overlay_file
        .parent()
        .ok_or_else(|| InstanceCliError::InvalidOverlayPath(overlay_file.to_path_buf()))?;
    let lock_path = config_directory.join(".lara-config.lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|error| io_error("open configuration lock", &lock_path, error))?;
    lock.lock()
        .map_err(|error| io_error("lock configuration directory", &lock_path, error))?;
    let current_overlay = fs::read_to_string(overlay_file)
        .map_err(|error| io_error("re-read production overlay", overlay_file, error))?;
    if current_overlay != expected_overlay {
        return Err(InstanceCliError::ConcurrentModification(
            overlay_file.to_path_buf(),
        ));
    }
    let current = match fs::read(drop_in_file) {
        Ok(contents) => Some(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(io_error("re-read systemd drop-in", drop_in_file, error).into());
        }
    };
    if current.as_deref() != expected_existing {
        return Err(InstanceCliError::ConcurrentModification(
            drop_in_file.to_path_buf(),
        ));
    }
    fs::create_dir_all(drop_in_directory)
        .map_err(|error| io_error("create systemd drop-in directory", drop_in_directory, error))?;
    let backup = if current.is_some() {
        let backup = backup_path(drop_in_file);
        fs::copy(drop_in_file, &backup)
            .map_err(|error| io_error("back up systemd drop-in", drop_in_file, error))?;
        Some(backup)
    } else {
        None
    };
    atomic_write_with_mode(drop_in_file, contents, drop_in_directory, 0o644)?;
    sync_directory(drop_in_directory)?;
    File::unlock(&lock)
        .map_err(|error| io_error("unlock configuration directory", &lock_path, error))?;
    Ok(backup)
}

struct LoadedRegistry {
    overlay_file: PathBuf,
    source: String,
    document: DocumentMut,
    environment: Vec<(String, String)>,
    registry: ConfiguredInstanceRegistry,
}

impl LoadedRegistry {
    fn read(args: &InstanceConfigArgs) -> Result<Self, InstanceCliError> {
        let source = fs::read_to_string(&args.overlay_file)
            .map_err(|error| io_error("read production overlay", &args.overlay_file, error))?;
        let document = source.parse::<DocumentMut>()?;
        let environment = read_environment(&args.environment_file)?;
        let registry = validate_candidate(&source, &environment)?;
        Ok(Self {
            overlay_file: args.overlay_file.clone(),
            source,
            document,
            environment,
            registry,
        })
    }
}

fn read_environment(path: &Path) -> Result<Vec<(String, String)>, InstanceCliError> {
    dotenvy::from_path_iter(path)
        .and_then(|values| values.collect::<Result<Vec<_>, _>>())
        .map_err(|_| InstanceCliError::InvalidEnvironmentFile(path.to_path_buf()))
}

fn validate_candidate(
    source: &str,
    environment: &[(String, String)],
) -> Result<ConfiguredInstanceRegistry, InstanceCliError> {
    let config = AppConfig::load_explicit_toml(source, environment.iter().cloned())?;
    Ok(ConfiguredInstanceRegistry::from_config(
        &config.game_server,
    )?)
}

fn materialize_primary(
    document: &mut DocumentMut,
    registry: &ConfiguredInstanceRegistry,
) -> Result<(), InstanceCliError> {
    if document
        .get("game_server")
        .and_then(|item| item.get("instances"))
        .and_then(Item::as_array_of_tables)
        .is_some_and(|instances| !instances.is_empty())
    {
        return Ok(());
    }
    let primary = registry.primary();
    let mut instances = ArrayOfTables::new();
    instances.push(instance_table(&primary, None, None));
    document["game_server"]["instances"] = Item::ArrayOfTables(instances);
    Ok(())
}

fn auxiliary_table(args: &InstanceAddArgs) -> Table {
    let unit = args
        .systemd_unit
        .clone()
        .unwrap_or_else(|| format!("lara-game@{}.service", args.id));
    let mut table = Table::new();
    table["id"] = value(&args.id);
    table["display_name"] = value(&args.display_name);
    table["kind"] = value("auxiliary");
    table["environment"] = value(environment_name(args.environment));
    table["sort_order"] = value(i64::from(args.sort_order));
    table["management"] = value("systemd");
    table["systemd_unit"] = value(unit);
    table["storage_root"] = value(path_value(&args.storage_root));
    table["capabilities"] = Item::Value(Value::Array(capability_array(&args.capabilities)));
    table["readiness"] = value("process");
    table["incident_tracking"] = value(true);
    table
}

fn instance_table(
    instance: &ServerInstance,
    systemd_unit: Option<&str>,
    storage_root: Option<&Path>,
) -> Table {
    let mut table = Table::new();
    table["id"] = value(instance.id().as_str());
    table["display_name"] = value(instance.display_name());
    table["kind"] = value(kind_name(instance.kind()));
    table["environment"] = value(domain_environment_name(instance.environment()));
    table["sort_order"] = value(i64::from(instance.sort_order()));
    table["management"] = value(management_name(instance.management()));
    if let Some(systemd_unit) = systemd_unit {
        table["systemd_unit"] = value(systemd_unit);
    }
    if let Some(storage_root) = storage_root {
        table["storage_root"] = value(path_value(storage_root));
    }
    let mut capabilities = Array::new();
    for capability in instance.capabilities().iter() {
        capabilities.push(capability_name(capability));
    }
    table["capabilities"] = Item::Value(Value::Array(capabilities));
    table["readiness"] = value(readiness_name(instance.observability().readiness()));
    table["incident_tracking"] = value(instance.observability().incident_tracking());
    table
}

fn instances_mut(document: &mut DocumentMut) -> Result<&mut ArrayOfTables, InstanceCliError> {
    document["game_server"]["instances"]
        .as_array_of_tables_mut()
        .ok_or(InstanceCliError::InvalidInstancesTable)
}

fn find_instance_mut<'a>(
    document: &'a mut DocumentMut,
    id: &str,
) -> Result<&'a mut Table, InstanceCliError> {
    instances_mut(document)?
        .iter_mut()
        .find(|table| table_id(table) == Some(id))
        .ok_or_else(|| InstanceCliError::NotFound(id.to_owned()))
}

fn table_id(table: &Table) -> Option<&str> {
    table.get("id").and_then(Item::as_str)
}

fn reject_primary(registry: &ConfiguredInstanceRegistry, id: &str) -> Result<(), InstanceCliError> {
    let instance = registry
        .list()
        .into_iter()
        .find(|instance| instance.id().as_str() == id)
        .ok_or_else(|| InstanceCliError::NotFound(id.to_owned()))?;
    if instance.kind() == InstanceKind::Primary {
        return Err(InstanceCliError::PrimaryImmutable(id.to_owned()));
    }
    Ok(())
}

fn commit_overlay(
    overlay: &Path,
    expected_source: &str,
    candidate: &[u8],
) -> Result<PathBuf, InstanceCliError> {
    let directory = overlay
        .parent()
        .ok_or_else(|| InstanceCliError::InvalidOverlayPath(overlay.to_path_buf()))?;
    let lock_path = directory.join(".lara-config.lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|error| io_error("open configuration lock", &lock_path, error))?;
    lock.lock()
        .map_err(|error| io_error("lock configuration directory", &lock_path, error))?;
    let current = fs::read_to_string(overlay)
        .map_err(|error| io_error("re-read production overlay", overlay, error))?;
    if current != expected_source {
        return Err(InstanceCliError::ConcurrentModification(
            overlay.to_path_buf(),
        ));
    }
    let backup = backup_path(overlay);
    fs::copy(overlay, &backup)
        .map_err(|error| io_error("back up production overlay", overlay, error))?;
    atomic_write(overlay, candidate, directory)?;
    sync_directory(directory)?;
    File::unlock(&lock)
        .map_err(|error| io_error("unlock configuration directory", &lock_path, error))?;
    Ok(backup)
}

fn capability_array(capabilities: &[InstanceCapabilityArg]) -> Array {
    let mut result = Array::new();
    for capability in capabilities {
        result.push(match capability {
            InstanceCapabilityArg::Overview => "overview",
            InstanceCapabilityArg::Lifecycle => "lifecycle",
            InstanceCapabilityArg::Configuration => "configuration",
            InstanceCapabilityArg::Incidents => "incidents",
        });
    }
    result
}

fn environment_name(environment: InstanceEnvironmentArg) -> &'static str {
    match environment {
        InstanceEnvironmentArg::Production => "production",
        InstanceEnvironmentArg::Development => "development",
        InstanceEnvironmentArg::Testing => "testing",
    }
}

fn path_value(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn instance_view(
    registry: &ConfiguredInstanceRegistry,
    instance: &ServerInstance,
) -> Result<InstanceView, InstanceCliError> {
    let configured = registry
        .configured(instance.id())
        .ok_or_else(|| InstanceCliError::NotFound(instance.id().to_string()))?;
    Ok(InstanceView {
        id: instance.id().to_string(),
        display_name: instance.display_name().to_owned(),
        kind: kind_name(instance.kind()),
        environment: domain_environment_name(instance.environment()),
        management: management_name(instance.management()),
        systemd_unit: configured
            .systemd_unit()
            .map(|unit| unit.as_str().to_owned()),
        storage_root: configured.storage_root().to_path_buf(),
        capabilities: instance
            .capabilities()
            .iter()
            .map(capability_name)
            .collect(),
        readiness: readiness_name(instance.observability().readiness()),
        incident_tracking: instance.observability().incident_tracking(),
        sort_order: instance.sort_order(),
    })
}

const fn kind_name(kind: InstanceKind) -> &'static str {
    match kind {
        InstanceKind::Primary => "primary",
        InstanceKind::Auxiliary => "auxiliary",
    }
}

const fn domain_environment_name(environment: InstanceEnvironment) -> &'static str {
    match environment {
        InstanceEnvironment::Production => "production",
        InstanceEnvironment::Development => "development",
        InstanceEnvironment::Testing => "testing",
    }
}

const fn management_name(management: InstanceManagement) -> &'static str {
    match management {
        InstanceManagement::External => "external",
        InstanceManagement::Systemd => "systemd",
    }
}

const fn readiness_name(readiness: InstanceReadiness) -> &'static str {
    match readiness {
        InstanceReadiness::Process => "process",
        InstanceReadiness::Uds => "uds",
    }
}

const fn capability_name(capability: InstanceCapability) -> &'static str {
    match capability {
        InstanceCapability::Overview => "overview",
        InstanceCapability::Lifecycle => "lifecycle",
        InstanceCapability::Configuration => "configuration",
        InstanceCapability::Maps => "maps",
        InstanceCapability::Backups => "backups",
        InstanceCapability::Incidents => "incidents",
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstanceListResult {
    primary_instance: String,
    instances: Vec<InstanceView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstanceView {
    id: String,
    display_name: String,
    kind: &'static str,
    environment: &'static str,
    management: &'static str,
    systemd_unit: Option<String>,
    storage_root: PathBuf,
    capabilities: Vec<&'static str>,
    readiness: &'static str,
    incident_tracking: bool,
    sort_order: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MutationResult {
    action: &'static str,
    instance: InstanceView,
    overlay_file: PathBuf,
    backup: Option<PathBuf>,
    dry_run: bool,
    storage_files_changed: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemdRenderResult {
    instance_id: String,
    systemd_unit: String,
    storage_root: PathBuf,
    executable: PathBuf,
    user: String,
    group: String,
    drop_in_file: PathBuf,
    environment_file: PathBuf,
    protect_home: bool,
    dry_run: bool,
    changed: bool,
    backup: Option<PathBuf>,
    daemon_reloaded: bool,
    generated_contents: String,
    acl_guidance: Vec<String>,
}

#[derive(Debug, Error)]
pub enum InstanceCliError {
    #[error("instance `{0}` is already registered")]
    AlreadyExists(String),
    #[error("instance `{0}` is not registered")]
    NotFound(String),
    #[error("primary instance `{0}` cannot be edited or removed in Release B")]
    PrimaryImmutable(String),
    #[error("instance `{0}` is not a systemd-managed auxiliary")]
    NotSystemdManaged(String),
    #[error("instance edit requires at least one changed field")]
    NoChanges,
    #[error("removing instance `{0}` requires --yes (or use --dry-run)")]
    ConfirmationRequired(String),
    #[error("the production overlay has no editable [[game_server.instances]] registry")]
    InvalidInstancesTable,
    #[error("invalid production overlay path: {0}")]
    InvalidOverlayPath(PathBuf),
    #[error("production overlay changed while the command was running: {0}")]
    ConcurrentModification(PathBuf),
    #[error("replacing systemd drop-in `{}` requires --yes (or use --dry-run)", .0.display())]
    DropInConfirmationRequired(PathBuf),
    #[error("{name} must be an absolute path: {}", path.display())]
    PathMustBeAbsolute { name: &'static str, path: PathBuf },
    #[error("path contains characters with unsafe systemd expansion semantics: {}", .0.display())]
    UnsafeSystemdPath(PathBuf),
    #[error("systemd path is not valid UTF-8: {}", .0.display())]
    NonUtf8SystemdPath(PathBuf),
    #[error("instance storage root must be a real directory, not a symlink: {}", .0.display())]
    InvalidStorageRoot(PathBuf),
    #[error("game-server executable is not a regular file: {}", .0.display())]
    InvalidExecutable(PathBuf),
    #[error("game-server executable is not marked executable: {}", .0.display())]
    #[cfg(unix)]
    ExecutablePermission(PathBuf),
    #[error("executable `{}` is outside storage root `{}`", executable.display(), storage_root.display())]
    ExecutableOutsideStorageRoot {
        executable: PathBuf,
        storage_root: PathBuf,
    },
    #[error("invalid Unix user or group name `{0}`")]
    InvalidUnixIdentity(String),
    #[error("Unix user or group `{0}` does not exist")]
    #[cfg(unix)]
    UnixIdentityNotFound(String),
    #[error("environment file is missing or invalid: {0}")]
    InvalidEnvironmentFile(PathBuf),
    #[error(transparent)]
    ConfigCli(#[from] ConfigCliError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Registry(#[from] InstanceRegistryError),
    #[error("systemd drop-in was installed at `{}` but manager reload failed: {source}", path.display())]
    ReloadAfterInstall {
        path: PathBuf,
        #[source]
        source: SystemdReloadError,
    },
    #[error(transparent)]
    Toml(#[from] toml_edit::TomlError),
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    const ENVIRONMENT: &str = r#"
LARA_JWT__SECRET=environment-secret-with-32-bytes!
LARA_MFA__ENCRYPTION_KEY=1111111111111111111111111111111111111111111111111111111111111111
LARA_MYSQL__URL=mysql://lara:secret@localhost/lara
LARA_MONGODB__URI=mongodb://localhost:27017
"#;

    fn fixture(name: &str) -> (PathBuf, InstanceConfigArgs) {
        let directory = std::env::temp_dir().join(format!(
            "lara-instance-cli-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        let overlay = directory.join("production.toml");
        let environment = directory.join("lara.env");
        fs::write(
            &overlay,
            include_str!("assets/production.toml").replace("/srv/openmp/main", "/srv/main"),
        )
        .unwrap();
        fs::write(&environment, ENVIRONMENT).unwrap();
        (
            directory,
            InstanceConfigArgs {
                overlay_file: overlay,
                environment_file: environment,
                output: OutputFormat::Json,
            },
        )
    }

    fn add_args(config: InstanceConfigArgs, dry_run: bool) -> InstanceAddArgs {
        InstanceAddArgs {
            id: "test".into(),
            display_name: "Test server".into(),
            environment: InstanceEnvironmentArg::Testing,
            storage_root: PathBuf::from("/home/svr_test"),
            capabilities: vec![
                InstanceCapabilityArg::Overview,
                InstanceCapabilityArg::Lifecycle,
                InstanceCapabilityArg::Configuration,
                InstanceCapabilityArg::Incidents,
            ],
            sort_order: 20,
            systemd_unit: None,
            dry_run,
            config,
        }
    }

    #[test]
    fn add_dry_run_materializes_primary_but_does_not_write() {
        let (directory, config) = fixture("add-dry-run");
        let before = fs::read_to_string(&config.overlay_file).unwrap();
        add(add_args(config.clone(), true)).unwrap();
        assert_eq!(fs::read_to_string(&config.overlay_file).unwrap(), before);
        assert!(!directory.join(".lara-config.lock").exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_overlapping_storage_roots_before_any_write() {
        let (directory, config) = fixture("overlap");
        let mut args = add_args(config.clone(), true);
        args.storage_root = PathBuf::from("/srv/main/child");
        assert!(matches!(
            add(args),
            Err(InstanceCliError::Registry(
                InstanceRegistryError::OverlappingStorageRoots { .. }
            ))
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn removal_requires_confirmation_and_never_touches_storage() {
        let (directory, config) = fixture("remove");
        let loaded = LoadedRegistry::read(&config).unwrap();
        let mut document = loaded.document.clone();
        materialize_primary(&mut document, &loaded.registry).unwrap();
        instances_mut(&mut document)
            .unwrap()
            .push(auxiliary_table(&add_args(config.clone(), true)));
        fs::write(&config.overlay_file, document.to_string()).unwrap();
        let storage = directory.join("server-files");
        fs::create_dir_all(&storage).unwrap();
        fs::write(storage.join("keep.txt"), "keep").unwrap();

        let result = remove(InstanceRemoveArgs {
            id: "test".into(),
            yes: false,
            dry_run: false,
            config,
        });
        assert!(matches!(
            result,
            Err(InstanceCliError::ConfirmationRequired(_))
        ));
        assert_eq!(
            fs::read_to_string(storage.join("keep.txt")).unwrap(),
            "keep"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn renderer_disables_protect_home_only_for_home_roots() {
        let home = render_drop_in(
            Path::new("/home/svr_test"),
            Path::new("/home/svr_test/omp-server"),
            Path::new("/etc/lara/game-instances/test.env"),
            "lara-game",
            "lara-game",
            true,
        )
        .unwrap();
        assert!(home.contains("WorkingDirectory=\"/home/svr_test\""));
        assert!(home.contains("ExecStart=\"/home/svr_test/omp-server\""));
        assert!(home.contains("ProtectHome=no"));
        assert!(home.contains("ReadWritePaths=\"/home/svr_test\""));
        assert!(!home.contains("start "));

        let srv = render_drop_in(
            Path::new("/srv/openmp/test"),
            Path::new("/srv/openmp/test/omp-server"),
            Path::new("/etc/lara/game-instances/test.env"),
            "lara-game",
            "lara-game",
            false,
        )
        .unwrap();
        assert!(srv.contains("ProtectHome=yes"));
    }

    #[test]
    fn systemd_paths_reject_specifier_and_environment_expansion() {
        for unsafe_path in ["/srv/openmp/%i", "/srv/openmp/$INSTANCE"] {
            assert!(matches!(
                quote_systemd_path(Path::new(unsafe_path)),
                Err(InstanceCliError::UnsafeSystemdPath(_))
            ));
        }
        assert!(matches!(
            validate_identity("lara game", IdentityKind::User),
            Err(InstanceCliError::InvalidUnixIdentity(_))
        ));
    }
}
