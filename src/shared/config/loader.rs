use std::{
    collections::HashSet,
    env,
    path::{Component, Path, PathBuf},
};

use ::config::{ConfigBuilder, Environment, File, FileFormat, Map, builder::DefaultState};

use super::{AppConfig, ConfigError};
use crate::shared::config::model::{
    BackupCompression, EffectiveInstanceConfigurationConfig, FileStorageConfig,
    InstanceCapabilityConfig, InstanceConfigurationConfig, InstanceKindConfig,
    ServerInstanceConfig,
};
use crate::shared::file_storage::path::{RelativeStoragePath, StorageFileName};

const EMBEDDED_DEFAULT_CONFIG: &str = include_str!("../../../config/default.toml");
const CONFIG_FILE_ENV: &str = "LARA_CONFIG_FILE";
const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:3000";
const DEFAULT_JWT_TTL_SECONDS: i64 = 3_600;
const MIN_JWT_TTL_SECONDS: i64 = 60;
const MAX_JWT_TTL_SECONDS: i64 = 86_400;
const MIN_JWT_SECRET_BYTES: usize = 32;
const MFA_ENCRYPTION_KEY_BYTES: usize = 32;
const MIN_MFA_CHALLENGE_TTL_SECONDS: u64 = 60;
const MAX_MFA_CHALLENGE_TTL_SECONDS: u64 = 15 * 60;
const MIN_MFA_ENROLLMENT_TTL_SECONDS: u64 = 60;
const MAX_MFA_ENROLLMENT_TTL_SECONDS: u64 = 60 * 60;
const MIN_MFA_VERIFICATION_ATTEMPTS: u64 = 1;
const MAX_MFA_VERIFICATION_ATTEMPTS: u64 = 10;
const MIN_TOTP_PERIOD_SECONDS: u64 = 15;
const MAX_TOTP_PERIOD_SECONDS: u64 = 5 * 60;
const MAX_TOTP_CLOCK_SKEW_STEPS: u64 = 2;
const MIN_TREE_DEPTH: u64 = 1;
const MAX_TREE_DEPTH: u64 = 128;
const MIN_TREE_ENTRIES: u64 = 1;
const MAX_TREE_ENTRIES: u64 = 1_000_000;
const MIN_STREAM_SIZE_BYTES: u64 = 1;
const MAX_STREAM_SIZE_BYTES: u64 = 1024 * 1024 * 1024;
const MIN_MAP_FILES_PER_REQUEST: u64 = 1;
const MAX_MAP_FILES_PER_REQUEST: u64 = 1_000;
const MAX_MAP_BATCH_SIZE_BYTES: u64 = 1024 * 1024 * 1024;
const DEFAULT_BACKUP_DIRECTORY: &str = "./data/backups";
const DEFAULT_BACKUP_COMPRESSION: &str = "gzip";
const DEFAULT_BACKUP_COMPRESSION_LEVEL: u32 = 1;
const DEFAULT_BACKUP_COMPRESSION_THRESHOLD_BYTES: u64 = 1024 * 1024;
const DEFAULT_BACKUP_LIFETIME_SECONDS: u64 = 14 * 24 * 60 * 60;
const DEFAULT_BACKUP_CLEANUP_INTERVAL_SECONDS: u64 = 60 * 60;
const DEFAULT_BACKUP_CLEANUP_BATCH_SIZE: u64 = 50;
const DEFAULT_BACKUP_MAX_CONCURRENT_DELETIONS: u64 = 8;
const DEFAULT_BACKUP_OPERATION_LEASE_SECONDS: u64 = 5 * 60;
const DEFAULT_BACKUP_STALE_PREPARATION_SECONDS: u64 = 30 * 60;
const DEFAULT_BACKUP_DIFF_ENABLED: bool = true;
const DEFAULT_BACKUP_DIFF_MAX_INPUT_SIZE_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_BACKUP_DIFF_GENERATION_TIMEOUT_MS: u64 = 5_000;
const MAX_BACKUP_LIFETIME_SECONDS: u64 = 10 * 365 * 24 * 60 * 60;
const MAX_BACKUP_CLEANUP_BATCH_SIZE: u64 = 1_000;
const MAX_BACKUP_CONCURRENT_DELETIONS: u64 = 64;
const MAX_BACKUP_LEASE_SECONDS: u64 = 24 * 60 * 60;
const MAX_BACKUP_STALE_PREPARATION_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_BACKUP_DIFF_TIMEOUT_MS: u64 = 60_000;

impl AppConfig {
    /// Resolves and validates the configuration policy for one registration.
    /// The result belongs to the configuration context's future target catalog;
    /// it is intentionally absent from the server-instance domain model.
    pub fn effective_configuration_policy(
        &self,
        instance: &ServerInstanceConfig,
    ) -> Result<Option<EffectiveInstanceConfigurationConfig>, ConfigError> {
        let has_capability = instance
            .capabilities
            .contains(&InstanceCapabilityConfig::Configuration);
        if !has_capability {
            return if instance.configuration.is_some() {
                Err(ConfigError::UnexpectedInstanceConfiguration(
                    instance.id.clone(),
                ))
            } else {
                Ok(None)
            };
        }
        if instance.kind == InstanceKindConfig::Auxiliary && instance.configuration.is_none() {
            return Err(ConfigError::MissingInstanceConfiguration(
                instance.id.clone(),
            ));
        }

        self.resolve_configuration_policy(instance.configuration.as_ref(), &instance.id)
            .map(Some)
    }

    /// Effective policy for the implicit primary used by legacy deployments.
    pub fn implicit_primary_configuration_policy(
        &self,
    ) -> Result<EffectiveInstanceConfigurationConfig, ConfigError> {
        self.resolve_configuration_policy(None, &self.game_server.primary_instance)
    }

    fn resolve_configuration_policy(
        &self,
        override_policy: Option<&InstanceConfigurationConfig>,
        instance_id: &str,
    ) -> Result<EffectiveInstanceConfigurationConfig, ConfigError> {
        let defaults = &self.configuration.files;
        let storage = &self.game_server.storage;
        let policy = EffectiveInstanceConfigurationConfig {
            fallback_encoding: override_policy
                .and_then(|value| value.fallback_encoding.clone())
                .unwrap_or_else(|| defaults.fallback_encoding.clone()),
            binary_extensions: override_policy
                .and_then(|value| value.binary_extensions.clone())
                .unwrap_or_else(|| defaults.binary_extensions.clone()),
            binary_file_names: override_policy
                .and_then(|value| value.binary_file_names.clone())
                .unwrap_or_else(|| defaults.binary_file_names.clone()),
            ignored_paths: override_policy
                .and_then(|value| value.ignored_paths.clone())
                .unwrap_or_else(|| defaults.ignored_paths.clone()),
            artifact_paths: override_policy
                .map(|value| value.artifact_paths.clone())
                .unwrap_or_default(),
            max_tree_depth: override_policy
                .and_then(|value| value.max_tree_depth)
                .unwrap_or(storage.max_tree_depth),
            max_tree_entries: override_policy
                .and_then(|value| value.max_tree_entries)
                .unwrap_or(storage.max_tree_entries),
            max_file_size_bytes: override_policy
                .and_then(|value| value.max_file_size_bytes)
                .unwrap_or(storage.max_stream_size_bytes),
        };
        validate_effective_configuration_policy(&policy, storage).map_err(|reason| {
            ConfigError::InvalidInstanceConfiguration {
                instance: instance_id.to_owned(),
                reason,
            }
        })?;
        Ok(policy)
    }

    /// Loads configuration in ascending priority order:
    /// built-in scalars, embedded default TOML, an explicitly selected TOML,
    /// deprecated environment names, and finally `LARA_*` variables.
    pub fn load() -> Result<Self, ConfigError> {
        let mut builder = base_builder()?;

        if let Some(path) = nonempty_env(CONFIG_FILE_ENV) {
            tracing::info!(config_file = %path, "loading configuration overlay");
            builder = builder.add_source(File::from(Path::new(&path)).required(true));
        }

        builder = apply_legacy_environment(builder)?;
        builder = builder.add_source(lara_environment(None));

        deserialize_and_validate(builder)
    }

    /// Loads a mandatory overlay and an environment-file projection before
    /// applying the current process environment. This is used by the admin
    /// CLI without mutating global environment variables.
    pub fn load_explicit(
        overlay: &Path,
        environment: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ConfigError> {
        Self::load_explicit_source(
            File::from(overlay).required(true),
            environment.into_iter().collect(),
        )
    }

    /// Validates an in-memory TOML overlay using the exact same defaults and
    /// environment projection as daemon startup. Administrative mutations use
    /// this before atomically replacing the host file.
    pub fn load_explicit_toml(
        overlay: &str,
        environment: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ConfigError> {
        Self::load_explicit_source(
            File::from_str(overlay, FileFormat::Toml),
            environment.into_iter().collect(),
        )
    }

    fn load_explicit_source<T>(
        overlay: T,
        environment: Map<String, String>,
    ) -> Result<Self, ConfigError>
    where
        T: ::config::Source + Send + Sync + 'static,
    {
        let mut builder = base_builder()?
            .add_source(overlay)
            .add_source(lara_environment(Some(environment)));
        builder = apply_legacy_environment(builder)?;
        builder = builder.add_source(lara_environment(None));
        deserialize_and_validate(builder)
    }
}

fn base_builder() -> Result<ConfigBuilder<DefaultState>, ConfigError> {
    Ok(::config::Config::builder()
        .set_default("server.bind_address", DEFAULT_BIND_ADDRESS)?
        .set_default("jwt.ttl_seconds", DEFAULT_JWT_TTL_SECONDS)?
        .set_default("backups.storage.directory", DEFAULT_BACKUP_DIRECTORY)?
        .set_default("backups.storage.compression", DEFAULT_BACKUP_COMPRESSION)?
        .set_default(
            "backups.storage.compression_level",
            DEFAULT_BACKUP_COMPRESSION_LEVEL,
        )?
        .set_default(
            "backups.storage.compression_threshold_bytes",
            DEFAULT_BACKUP_COMPRESSION_THRESHOLD_BYTES,
        )?
        .set_default(
            "backups.retention.lifetime_seconds",
            DEFAULT_BACKUP_LIFETIME_SECONDS,
        )?
        .set_default(
            "backups.retention.cleanup_interval_seconds",
            DEFAULT_BACKUP_CLEANUP_INTERVAL_SECONDS,
        )?
        .set_default(
            "backups.retention.cleanup_batch_size",
            DEFAULT_BACKUP_CLEANUP_BATCH_SIZE,
        )?
        .set_default(
            "backups.retention.max_concurrent_deletions",
            DEFAULT_BACKUP_MAX_CONCURRENT_DELETIONS,
        )?
        .set_default(
            "backups.retention.operation_lease_seconds",
            DEFAULT_BACKUP_OPERATION_LEASE_SECONDS,
        )?
        .set_default(
            "backups.retention.stale_preparation_seconds",
            DEFAULT_BACKUP_STALE_PREPARATION_SECONDS,
        )?
        .set_default("backups.diff.enabled", DEFAULT_BACKUP_DIFF_ENABLED)?
        .set_default(
            "backups.diff.max_input_size_bytes",
            DEFAULT_BACKUP_DIFF_MAX_INPUT_SIZE_BYTES,
        )?
        .set_default(
            "backups.diff.generation_timeout_ms",
            DEFAULT_BACKUP_DIFF_GENERATION_TIMEOUT_MS,
        )?
        // Keep the production binary independent from its current working
        // directory. The committed, non-secret defaults are compiled into
        // the executable; deployment files only override them.
        .add_source(File::from_str(EMBEDDED_DEFAULT_CONFIG, FileFormat::Toml)))
}

fn deserialize_and_validate(
    builder: ConfigBuilder<DefaultState>,
) -> Result<AppConfig, ConfigError> {
    let config = builder.build()?.try_deserialize::<AppConfig>()?;
    config.validate()?;
    log_loaded_configuration(&config);
    Ok(config)
}

impl AppConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        require_nonempty("jwt.secret", self.jwt.secret.expose_secret())?;
        require_nonempty("jwt.issuer", &self.jwt.issuer)?;
        require_nonempty("jwt.audience", &self.jwt.audience)?;
        require_nonempty(
            "mfa.encryption_key",
            self.mfa.encryption_key.expose_secret(),
        )?;
        require_nonempty("mfa.issuer", &self.mfa.issuer)?;
        require_nonempty("mysql.url", self.mysql.url.expose_secret())?;
        require_nonempty("mongodb.uri", self.mongodb.uri.expose_secret())?;
        require_nonempty("mongodb.database", &self.mongodb.database)?;
        require_nonempty_path("game_server.storage.root", &self.game_server.storage.root)?;
        require_nonempty_path("backups.storage.directory", &self.backups.storage.directory)?;
        require_relative_path(
            "configuration.files.configurator_directory",
            &self.configuration.files.configurator_directory,
        )?;
        require_relative_path("maps.files.directory", &self.maps.files.directory)?;

        if self.jwt.secret.expose_secret().len() < MIN_JWT_SECRET_BYTES {
            return Err(ConfigError::JwtSecretTooShort {
                minimum: MIN_JWT_SECRET_BYTES,
            });
        }

        validate_mfa_encryption_key(self.mfa.encryption_key.expose_secret())?;
        require_range(
            "mfa.challenge_ttl_seconds",
            self.mfa.challenge_ttl_seconds,
            MIN_MFA_CHALLENGE_TTL_SECONDS,
            MAX_MFA_CHALLENGE_TTL_SECONDS,
        )?;
        require_range(
            "mfa.enrollment_ttl_seconds",
            self.mfa.enrollment_ttl_seconds,
            MIN_MFA_ENROLLMENT_TTL_SECONDS,
            MAX_MFA_ENROLLMENT_TTL_SECONDS,
        )?;
        require_range(
            "mfa.max_verification_attempts",
            u64::from(self.mfa.max_verification_attempts),
            MIN_MFA_VERIFICATION_ATTEMPTS,
            MAX_MFA_VERIFICATION_ATTEMPTS,
        )?;
        require_range(
            "mfa.totp_period_seconds",
            self.mfa.totp_period_seconds,
            MIN_TOTP_PERIOD_SECONDS,
            MAX_TOTP_PERIOD_SECONDS,
        )?;
        if !matches!(self.mfa.totp_digits, 6 | 8) {
            return Err(ConfigError::InvalidMfaTotpDigits);
        }
        require_range(
            "mfa.allowed_clock_skew_steps",
            u64::from(self.mfa.allowed_clock_skew_steps),
            0,
            MAX_TOTP_CLOCK_SKEW_STEPS,
        )?;

        parse_jwt_ttl_seconds(&self.jwt.ttl_seconds.to_string())?;
        require_range(
            "game_server.storage.max_tree_depth",
            self.game_server.storage.max_tree_depth as u64,
            MIN_TREE_DEPTH,
            MAX_TREE_DEPTH,
        )?;
        require_range(
            "game_server.storage.max_tree_entries",
            self.game_server.storage.max_tree_entries as u64,
            MIN_TREE_ENTRIES,
            MAX_TREE_ENTRIES,
        )?;
        require_range(
            "game_server.storage.max_stream_size_bytes",
            self.game_server.storage.max_stream_size_bytes,
            MIN_STREAM_SIZE_BYTES,
            MAX_STREAM_SIZE_BYTES,
        )?;
        validate_binary_extensions(&self.configuration.files.binary_extensions)?;
        validate_binary_file_names(&self.configuration.files.binary_file_names)?;
        validate_ignored_paths(&self.configuration.files.ignored_paths)?;
        validate_text_encoding(&self.configuration.files.fallback_encoding)?;
        for instance in &self.game_server.instances {
            self.effective_configuration_policy(instance)?;
        }
        require_range(
            "maps.upload.max_files_per_request",
            self.maps.upload.max_files_per_request as u64,
            MIN_MAP_FILES_PER_REQUEST,
            MAX_MAP_FILES_PER_REQUEST,
        )?;
        require_range(
            "maps.upload.max_file_size_bytes",
            self.maps.upload.max_file_size_bytes,
            MIN_STREAM_SIZE_BYTES,
            self.game_server.storage.max_stream_size_bytes,
        )?;
        require_range(
            "maps.upload.max_total_size_bytes",
            self.maps.upload.max_total_size_bytes,
            self.maps.upload.max_file_size_bytes,
            MAX_MAP_BATCH_SIZE_BYTES,
        )?;
        let primary_storage_root = self
            .game_server
            .instances
            .iter()
            .find(|instance| instance.id == self.game_server.primary_instance)
            .and_then(|instance| instance.storage_root.as_deref())
            .unwrap_or(&self.game_server.storage.root);
        validate_backup_directory(primary_storage_root, &self.backups.storage.directory)?;
        validate_backup_compression(
            self.backups.storage.compression,
            self.backups.storage.compression_level,
        )?;
        require_range(
            "backups.storage.compression_threshold_bytes",
            self.backups.storage.compression_threshold_bytes,
            0,
            self.game_server.storage.max_stream_size_bytes,
        )?;
        require_range(
            "backups.retention.lifetime_seconds",
            self.backups.retention.lifetime_seconds,
            60 * 60,
            MAX_BACKUP_LIFETIME_SECONDS,
        )?;
        require_range(
            "backups.retention.cleanup_interval_seconds",
            self.backups.retention.cleanup_interval_seconds,
            10,
            self.backups.retention.lifetime_seconds,
        )?;
        require_range(
            "backups.retention.cleanup_batch_size",
            self.backups.retention.cleanup_batch_size as u64,
            1,
            MAX_BACKUP_CLEANUP_BATCH_SIZE,
        )?;
        require_range(
            "backups.retention.max_concurrent_deletions",
            self.backups.retention.max_concurrent_deletions as u64,
            1,
            MAX_BACKUP_CONCURRENT_DELETIONS,
        )?;
        require_range(
            "backups.retention.operation_lease_seconds",
            self.backups.retention.operation_lease_seconds,
            30,
            MAX_BACKUP_LEASE_SECONDS,
        )?;
        require_range(
            "backups.retention.stale_preparation_seconds",
            self.backups.retention.stale_preparation_seconds,
            self.backups.retention.operation_lease_seconds,
            MAX_BACKUP_STALE_PREPARATION_SECONDS,
        )?;
        require_range(
            "backups.diff.max_input_size_bytes",
            self.backups.diff.max_input_size_bytes,
            1,
            self.game_server.storage.max_stream_size_bytes,
        )?;
        require_range(
            "backups.diff.generation_timeout_ms",
            self.backups.diff.generation_timeout_ms,
            10,
            MAX_BACKUP_DIFF_TIMEOUT_MS,
        )?;
        Ok(())
    }
}

fn log_loaded_configuration(config: &AppConfig) {
    tracing::info!(
        bind_address = %config.server.bind_address,
        jwt_issuer = %config.jwt.issuer,
        jwt_audience = %config.jwt.audience,
        jwt_ttl_seconds = config.jwt.ttl_seconds,
        mfa_issuer = %config.mfa.issuer,
        mfa_challenge_ttl_seconds = config.mfa.challenge_ttl_seconds,
        mfa_enrollment_ttl_seconds = config.mfa.enrollment_ttl_seconds,
        mfa_max_verification_attempts = config.mfa.max_verification_attempts,
        mfa_totp_period_seconds = config.mfa.totp_period_seconds,
        mfa_totp_digits = config.mfa.totp_digits,
        mfa_allowed_clock_skew_steps = config.mfa.allowed_clock_skew_steps,
        mongodb_database = %config.mongodb.database,
        file_storage_max_tree_depth = config.game_server.storage.max_tree_depth,
        file_storage_max_tree_entries = config.game_server.storage.max_tree_entries,
        file_storage_max_stream_size_bytes = config.game_server.storage.max_stream_size_bytes,
        maps_directory = %config.maps.files.directory.display(),
        maps_max_files_per_request = config.maps.upload.max_files_per_request,
        maps_max_file_size_bytes = config.maps.upload.max_file_size_bytes,
        maps_max_total_size_bytes = config.maps.upload.max_total_size_bytes,
        backups_directory = %config.backups.storage.directory.display(),
        backups_compression = ?config.backups.storage.compression,
        backups_lifetime_seconds = config.backups.retention.lifetime_seconds,
        backups_cleanup_interval_seconds = config.backups.retention.cleanup_interval_seconds,
        backups_diff_enabled = config.backups.diff.enabled,
        backups_diff_max_input_size_bytes = config.backups.diff.max_input_size_bytes,
        "server configuration loaded"
    );
}

fn lara_environment(source: Option<Map<String, String>>) -> Environment {
    Environment::with_prefix("LARA")
        .prefix_separator("_")
        .separator("__")
        .try_parsing(true)
        .list_separator(",")
        .with_list_parse_key("configuration.files.binary_extensions")
        .with_list_parse_key("configuration.files.binary_file_names")
        .with_list_parse_key("configuration.files.ignored_paths")
        .ignore_empty(true)
        .source(source)
}

fn apply_legacy_environment(
    builder: ConfigBuilder<DefaultState>,
) -> Result<ConfigBuilder<DefaultState>, ConfigError> {
    apply_legacy_environment_from(builder, &nonempty_env)
}

fn apply_legacy_environment_from<F>(
    mut builder: ConfigBuilder<DefaultState>,
    read: &F,
) -> Result<ConfigBuilder<DefaultState>, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    builder = legacy_string_override(
        builder,
        "server.bind_address",
        "BIND_ADDRESS",
        "LARA_SERVER__BIND_ADDRESS",
        read,
    )?;
    builder = legacy_string_override(
        builder,
        "mysql.url",
        "MYSQL_DATABASE_URL",
        "LARA_MYSQL__URL",
        read,
    )?;
    builder = legacy_string_override(
        builder,
        "mongodb.uri",
        "MONGODB_URI",
        "LARA_MONGODB__URI",
        read,
    )?;
    builder = legacy_string_override(
        builder,
        "mongodb.database",
        "MONGODB_DATABASE",
        "LARA_MONGODB__DATABASE",
        read,
    )?;
    builder = legacy_string_override(
        builder,
        "jwt.secret",
        "LSRV_SECRET",
        "LARA_JWT__SECRET",
        read,
    )?;
    builder = legacy_string_override(
        builder,
        "jwt.issuer",
        "JWT_ISSUER",
        "LARA_JWT__ISSUER",
        read,
    )?;
    builder = legacy_string_override(
        builder,
        "jwt.audience",
        "JWT_AUDIENCE",
        "LARA_JWT__AUDIENCE",
        read,
    )?;

    if read("LARA_JWT__TTL_SECONDS").is_none()
        && let Some(value) = read("JWT_TTL_SECONDS")
    {
        warn_legacy_environment("JWT_TTL_SECONDS", "LARA_JWT__TTL_SECONDS");
        builder = builder.set_override("jwt.ttl_seconds", parse_jwt_ttl_seconds(&value)?)?;
    }

    Ok(builder)
}

fn legacy_string_override(
    builder: ConfigBuilder<DefaultState>,
    key: &'static str,
    legacy_name: &'static str,
    replacement_name: &'static str,
    read: &impl Fn(&str) -> Option<String>,
) -> Result<ConfigBuilder<DefaultState>, ConfigError> {
    if read(replacement_name).is_some() {
        return Ok(builder);
    }

    match read(legacy_name) {
        Some(value) => {
            warn_legacy_environment(legacy_name, replacement_name);
            Ok(builder.set_override(key, value)?)
        }
        None => Ok(builder),
    }
}

fn warn_legacy_environment(legacy_name: &'static str, replacement_name: &'static str) {
    tracing::warn!(
        legacy_variable = legacy_name,
        replacement_variable = replacement_name,
        "deprecated configuration environment variable is in use"
    );
}

fn nonempty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn require_nonempty(key: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::EmptyValue { key });
    }

    Ok(())
}

fn require_nonempty_path(key: &'static str, value: &Path) -> Result<(), ConfigError> {
    if value.as_os_str().is_empty() {
        return Err(ConfigError::EmptyValue { key });
    }

    Ok(())
}

fn require_relative_path(key: &'static str, value: &Path) -> Result<(), ConfigError> {
    RelativeStoragePath::try_from(value)
        .map(|_| ())
        .map_err(|_| ConfigError::InvalidRelativePath { key })
}

fn validate_backup_directory(game_root: &Path, backup_root: &Path) -> Result<(), ConfigError> {
    let game_root = lexical_absolute(game_root)?;
    let backup_root = lexical_absolute(backup_root)?;

    if path_is_within(&backup_root, &game_root) {
        return Err(ConfigError::BackupDirectoryInsideGameServerRoot);
    }

    Ok(())
}

fn lexical_absolute(path: &Path) -> Result<PathBuf, ConfigError> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        env::current_dir()
            .map_err(ConfigError::ResolvePath)?
            .join(path)
    };
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized.file_name().is_some() {
                    normalized.pop();
                }
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }

    Ok(normalized)
}

fn path_is_within(candidate: &Path, root: &Path) -> bool {
    #[cfg(windows)]
    {
        let candidate = candidate
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        let root = root
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        candidate == root || candidate.starts_with(&format!("{}/", root.trim_end_matches('/')))
    }

    #[cfg(not(windows))]
    {
        candidate.starts_with(root)
    }
}

fn validate_backup_compression(
    compression: BackupCompression,
    level: u32,
) -> Result<(), ConfigError> {
    let (codec, minimum, maximum) = match compression {
        BackupCompression::None => ("none", 0, 0),
        BackupCompression::Gzip => ("gzip", 0, 9),
    };

    if !(minimum..=maximum).contains(&level) {
        return Err(ConfigError::InvalidBackupCompressionLevel {
            codec,
            level,
            minimum,
            maximum,
        });
    }

    Ok(())
}

fn require_range(
    key: &'static str,
    value: u64,
    minimum: u64,
    maximum: u64,
) -> Result<(), ConfigError> {
    if !(minimum..=maximum).contains(&value) {
        return Err(ConfigError::ValueOutOfRange {
            key,
            minimum,
            maximum,
        });
    }

    Ok(())
}

fn validate_binary_extensions(extensions: &[String]) -> Result<(), ConfigError> {
    let mut unique = HashSet::with_capacity(extensions.len());

    for extension in extensions {
        if extension.is_empty()
            || !extension
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(ConfigError::InvalidFileExtension {
                extension: extension.clone(),
            });
        }

        if !unique.insert(extension.as_str()) {
            return Err(ConfigError::DuplicateFileExtension {
                extension: extension.clone(),
            });
        }
    }

    Ok(())
}

fn validate_binary_file_names(names: &[String]) -> Result<(), ConfigError> {
    let mut unique = HashSet::with_capacity(names.len());

    for name in names {
        let normalized = name.to_ascii_lowercase();
        if StorageFileName::new(name).is_err() {
            return Err(ConfigError::InvalidFileName { name: name.clone() });
        }

        if !unique.insert(normalized) {
            return Err(ConfigError::DuplicateFileName { name: name.clone() });
        }
    }

    Ok(())
}

fn validate_ignored_paths(paths: &[std::path::PathBuf]) -> Result<(), ConfigError> {
    let mut unique = HashSet::with_capacity(paths.len());

    for path in paths {
        require_relative_path("configuration.files.ignored_paths", path)?;
        let normalized = path.to_string_lossy().to_ascii_lowercase();

        if !unique.insert(normalized.clone()) {
            return Err(ConfigError::DuplicateIgnoredPath { path: normalized });
        }
    }

    Ok(())
}

fn validate_text_encoding(encoding: &str) -> Result<(), ConfigError> {
    require_nonempty("configuration.files.fallback_encoding", encoding)?;

    if encoding_rs::Encoding::for_label(encoding.as_bytes()).is_none() {
        return Err(ConfigError::UnsupportedTextEncoding {
            encoding: encoding.to_owned(),
        });
    }

    Ok(())
}

fn validate_effective_configuration_policy(
    policy: &EffectiveInstanceConfigurationConfig,
    storage: &FileStorageConfig,
) -> Result<(), String> {
    validate_text_encoding(&policy.fallback_encoding).map_err(|error| error.to_string())?;
    validate_binary_extensions(&policy.binary_extensions).map_err(|error| error.to_string())?;
    validate_binary_file_names(&policy.binary_file_names).map_err(|error| error.to_string())?;
    validate_ignored_paths(&policy.ignored_paths).map_err(|error| error.to_string())?;

    for (name, value, maximum) in [
        (
            "max_tree_depth",
            policy.max_tree_depth as u64,
            storage.max_tree_depth as u64,
        ),
        (
            "max_tree_entries",
            policy.max_tree_entries as u64,
            storage.max_tree_entries as u64,
        ),
        (
            "max_file_size_bytes",
            policy.max_file_size_bytes,
            storage.max_stream_size_bytes,
        ),
    ] {
        if value == 0 || value > maximum {
            return Err(format!(
                "{name} must be between 1 and the game_server.storage limit {maximum}"
            ));
        }
    }

    let ignored = policy
        .ignored_paths
        .iter()
        .map(|path| RelativeStoragePath::try_from(path.as_path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("invalid ignored path: {error}"))?;
    for (index, first) in ignored.iter().enumerate() {
        for second in ignored.iter().skip(index + 1) {
            if first.is_within_case_insensitive(second) || second.is_within_case_insensitive(first)
            {
                return Err(format!("ignored paths `{first}` and `{second}` overlap"));
            }
        }
    }

    let binary_names: HashSet<_> = policy
        .binary_file_names
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    let binary_extensions: HashSet<_> = policy
        .binary_extensions
        .iter()
        .map(String::as_str)
        .collect();
    let mut unique_artifacts = HashSet::new();
    for configured_path in &policy.artifact_paths {
        let path = RelativeStoragePath::try_from(configured_path.as_path()).map_err(|error| {
            format!(
                "invalid artifact path `{}`: {error}",
                configured_path.display()
            )
        })?;
        if !unique_artifacts.insert(path.as_normalized_str().to_ascii_lowercase()) {
            return Err(format!("duplicate artifact path `{path}`"));
        }
        if ignored
            .iter()
            .any(|ignored_path| path.is_within_case_insensitive(ignored_path))
        {
            return Err(format!(
                "artifact path `{path}` is inside an ignored subtree"
            ));
        }
        let file_name = path
            .file_name()
            .expect("validated artifact path has a name");
        let normalized_name = file_name.to_ascii_lowercase();
        let extension = normalized_name
            .rsplit_once('.')
            .map(|(_, extension)| extension);
        if path.components().any(is_protected_artifact_component)
            || normalized_name.contains(".so.")
            || normalized_name.contains(".env.")
            || normalized_name.contains(".service.")
            || extension.is_some_and(is_protected_artifact_extension)
        {
            return Err(format!("artifact path `{path}` targets a protected file"));
        }
        if !binary_names.contains(&normalized_name)
            && !extension.is_some_and(|extension| binary_extensions.contains(extension))
        {
            return Err(format!(
                "artifact path `{path}` is not classified as binary by this instance policy"
            ));
        }
    }
    Ok(())
}

fn is_protected_artifact_component(component: &str) -> bool {
    let normalized = component.to_ascii_lowercase();
    normalized.starts_with('.')
        || matches!(
            normalized.as_str(),
            "omp-server" | "samp03svr" | "systemd" | "secrets" | "private"
        )
}

fn is_protected_artifact_extension(extension: &str) -> bool {
    matches!(
        extension,
        "env"
            | "so"
            | "dll"
            | "exe"
            | "dylib"
            | "bundle"
            | "service"
            | "socket"
            | "key"
            | "pem"
            | "p12"
            | "pfx"
    )
}

fn parse_jwt_ttl_seconds(value: &str) -> Result<i64, ConfigError> {
    let seconds = value
        .parse::<i64>()
        .map_err(|_| ConfigError::InvalidJwtTtl)?;

    (MIN_JWT_TTL_SECONDS..=MAX_JWT_TTL_SECONDS)
        .contains(&seconds)
        .then_some(seconds)
        .ok_or(ConfigError::InvalidJwtTtl)
}

fn validate_mfa_encryption_key(value: &str) -> Result<(), ConfigError> {
    let expected_hex_length = MFA_ENCRYPTION_KEY_BYTES * 2;
    if value.len() != expected_hex_length || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConfigError::InvalidMfaEncryptionKey {
            expected_bytes: MFA_ENCRYPTION_KEY_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::config::model::{
        InstanceEnvironmentConfig, InstanceManagementConfig, InstanceReadinessConfig,
    };

    type ConfigMutation = Box<dyn Fn(&mut AppConfig)>;

    fn valid_config() -> AppConfig {
        AppConfig {
            server: super::super::model::ServerConfig {
                bind_address: "127.0.0.1:3000".parse().unwrap(),
            },
            jwt: super::super::model::JwtConfig {
                secret: super::super::model::SecretString::new("a".repeat(MIN_JWT_SECRET_BYTES)),
                issuer: "lara".into(),
                audience: "lara-api".into(),
                ttl_seconds: DEFAULT_JWT_TTL_SECONDS,
            },
            mfa: super::super::model::MfaConfig {
                encryption_key: super::super::model::SecretString::new("11".repeat(32)),
                issuer: "Lara".into(),
                challenge_ttl_seconds: 300,
                enrollment_ttl_seconds: 600,
                max_verification_attempts: 5,
                totp_period_seconds: 30,
                totp_digits: 6,
                allowed_clock_skew_steps: 1,
            },
            mysql: super::super::model::MySqlConfig {
                url: super::super::model::SecretString::new("mysql://localhost/lara"),
            },
            mongodb: super::super::model::MongoConfig {
                uri: super::super::model::SecretString::new("mongodb://localhost:27017"),
                database: "lara".into(),
            },
            game_server: super::super::model::GameServerConfig {
                primary_instance: "main".into(),
                instances: vec![],
                storage: super::super::model::FileStorageConfig {
                    root: "D:/servers/openmp".into(),
                    max_tree_depth: 32,
                    max_tree_entries: 10_000,
                    max_stream_size_bytes: 10 * 1024 * 1024,
                },
            },
            configuration: super::super::model::ConfigurationConfig {
                files: super::super::model::ConfigurationFilesConfig {
                    configurator_directory: "scriptfiles/config".into(),
                    binary_extensions: vec!["amx".into(), "dff".into(), "txd".into()],
                    binary_file_names: vec!["omp-server".into(), "samp03svr".into()],
                    ignored_paths: vec!["logs".into()],
                    fallback_encoding: "windows-1251".into(),
                },
            },
            maps: super::super::model::MapsConfig {
                files: super::super::model::MapsFilesConfig {
                    directory: "scriptfiles/maps".into(),
                },
                upload: super::super::model::MapsUploadConfig {
                    max_files_per_request: 50,
                    max_file_size_bytes: 10 * 1024 * 1024,
                    max_total_size_bytes: 50 * 1024 * 1024,
                },
            },
            backups: super::super::model::BackupsConfig {
                storage: super::super::model::BackupStorageConfig {
                    directory: "D:/backups".into(),
                    compression: BackupCompression::Gzip,
                    compression_level: 1,
                    compression_threshold_bytes: 1024 * 1024,
                },
                retention: super::super::model::BackupRetentionConfig {
                    lifetime_seconds: DEFAULT_BACKUP_LIFETIME_SECONDS,
                    cleanup_interval_seconds: DEFAULT_BACKUP_CLEANUP_INTERVAL_SECONDS,
                    cleanup_batch_size: DEFAULT_BACKUP_CLEANUP_BATCH_SIZE as usize,
                    max_concurrent_deletions: DEFAULT_BACKUP_MAX_CONCURRENT_DELETIONS as usize,
                    operation_lease_seconds: DEFAULT_BACKUP_OPERATION_LEASE_SECONDS,
                    stale_preparation_seconds: DEFAULT_BACKUP_STALE_PREPARATION_SECONDS,
                },
                diff: super::super::model::BackupDiffConfig {
                    enabled: true,
                    max_input_size_bytes: DEFAULT_BACKUP_DIFF_MAX_INPUT_SIZE_BYTES,
                    generation_timeout_ms: DEFAULT_BACKUP_DIFF_GENERATION_TIMEOUT_MS,
                },
            },
        }
    }

    fn auxiliary_with_configuration() -> ServerInstanceConfig {
        ServerInstanceConfig {
            id: "test".into(),
            display_name: "Test server".into(),
            kind: InstanceKindConfig::Auxiliary,
            environment: InstanceEnvironmentConfig::Testing,
            sort_order: 20,
            management: Some(InstanceManagementConfig::Systemd),
            systemd_unit: Some("lara-game@test.service".into()),
            storage_root: Some("/srv/openmp/test".into()),
            capabilities: vec![
                InstanceCapabilityConfig::Overview,
                InstanceCapabilityConfig::Lifecycle,
                InstanceCapabilityConfig::Configuration,
            ],
            configuration: Some(InstanceConfigurationConfig::default()),
            readiness: Some(InstanceReadinessConfig::Process),
            incident_tracking: true,
            systemd_observation: None,
        }
    }

    #[test]
    fn resolves_primary_legacy_defaults_and_auxiliary_overrides() {
        let mut config = valid_config();
        let mut primary = auxiliary_with_configuration();
        primary.id = "main".into();
        primary.kind = InstanceKindConfig::Primary;
        primary.capabilities.push(InstanceCapabilityConfig::Maps);
        primary.capabilities.push(InstanceCapabilityConfig::Backups);
        primary.configuration = None;
        let primary_policy = config
            .effective_configuration_policy(&primary)
            .unwrap()
            .unwrap();
        assert_eq!(primary_policy.fallback_encoding, "windows-1251");
        assert_eq!(primary_policy.ignored_paths, vec![PathBuf::from("logs")]);
        assert!(primary_policy.artifact_paths.is_empty());

        let mut auxiliary = auxiliary_with_configuration();
        let overrides = auxiliary.configuration.as_mut().unwrap();
        overrides.fallback_encoding = Some("utf-8".into());
        overrides.ignored_paths = Some(vec!["cache".into()]);
        overrides.artifact_paths = vec!["gamemodes/test.amx".into()];
        overrides.max_file_size_bytes = Some(1024);
        let policy = config
            .effective_configuration_policy(&auxiliary)
            .unwrap()
            .unwrap();
        assert_eq!(policy.fallback_encoding, "utf-8");
        assert_eq!(policy.ignored_paths, vec![PathBuf::from("cache")]);
        assert_eq!(
            policy.artifact_paths,
            vec![PathBuf::from("gamemodes/test.amx")]
        );
        assert_eq!(policy.max_file_size_bytes, 1024);
        assert_eq!(
            policy.binary_extensions,
            config.configuration.files.binary_extensions
        );
        config.game_server.instances.push(auxiliary);
        config.validate().unwrap();
    }

    #[test]
    fn backup_directory_checks_effective_primary_storage_root() {
        let mut config = valid_config();
        let mut primary = auxiliary_with_configuration();
        primary.id = "main".into();
        primary.kind = InstanceKindConfig::Primary;
        primary.capabilities.push(InstanceCapabilityConfig::Maps);
        primary.capabilities.push(InstanceCapabilityConfig::Backups);
        primary.storage_root = Some("D:/different-primary".into());
        config.game_server.instances = vec![primary];
        config.backups.storage.directory = "D:/different-primary/backups".into();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::BackupDirectoryInsideGameServerRoot)
        ));
    }

    #[test]
    fn requires_auxiliary_policy_and_rejects_policy_without_capability() {
        let mut config = valid_config();
        let mut auxiliary = auxiliary_with_configuration();
        auxiliary.configuration = None;
        config.game_server.instances.push(auxiliary);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MissingInstanceConfiguration(id)) if id == "test"
        ));

        let mut without_capability = auxiliary_with_configuration();
        without_capability
            .capabilities
            .retain(|capability| *capability != InstanceCapabilityConfig::Configuration);
        config.game_server.instances = vec![without_capability];
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnexpectedInstanceConfiguration(id)) if id == "test"
        ));
    }

    #[test]
    fn rejects_unsafe_artifacts_paths_and_out_of_range_limits() {
        let cases = [
            vec!["../test.amx"],
            vec!["logs/test.amx"],
            vec!["gamemodes/test.cfg"],
            vec!["plugins/native.so"],
            vec![".secrets/test.amx"],
            vec!["gamemodes/test.amx", "GAMEMODES\\TEST.AMX"],
        ];
        for artifact_paths in cases {
            let mut config = valid_config();
            let mut auxiliary = auxiliary_with_configuration();
            auxiliary.configuration.as_mut().unwrap().artifact_paths =
                artifact_paths.into_iter().map(PathBuf::from).collect();
            config.game_server.instances.push(auxiliary);
            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidInstanceConfiguration { instance, .. }) if instance == "test"
            ));
        }

        for size in [0, 10 * 1024 * 1024 + 1] {
            let mut config = valid_config();
            let mut auxiliary = auxiliary_with_configuration();
            auxiliary
                .configuration
                .as_mut()
                .unwrap()
                .max_file_size_bytes = Some(size);
            config.game_server.instances.push(auxiliary);
            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidInstanceConfiguration { instance, .. }) if instance == "test"
            ));
        }
    }

    #[test]
    fn rejects_versioned_native_library_even_if_binary_name_is_allowlisted() {
        let mut config = valid_config();
        let mut auxiliary = auxiliary_with_configuration();
        let policy = auxiliary.configuration.as_mut().unwrap();
        policy.binary_file_names = Some(vec!["native.so.1".into()]);
        policy.artifact_paths = vec!["plugins/native.so.1".into()];
        config.game_server.instances.push(auxiliary);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidInstanceConfiguration { reason, .. }) if reason.contains("protected")
        ));
    }

    #[test]
    fn rejects_invalid_auxiliary_encoding_ignored_paths_and_tree_limits() {
        let invalid_policies: [fn(&mut InstanceConfigurationConfig); 4] = [
            |policy| policy.fallback_encoding = Some("unknown-encoding".into()),
            |policy| policy.ignored_paths = Some(vec!["logs".into(), "logs/old".into()]),
            |policy| policy.max_tree_depth = Some(0),
            |policy| policy.max_tree_entries = Some(10_001),
        ];

        for make_invalid in invalid_policies {
            let mut config = valid_config();
            let mut auxiliary = auxiliary_with_configuration();
            make_invalid(auxiliary.configuration.as_mut().unwrap());
            config.game_server.instances.push(auxiliary);
            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidInstanceConfiguration { instance, .. }) if instance == "test"
            ));
        }
    }

    #[test]
    fn production_overlay_deserializes_nested_auxiliary_policy() {
        let overlay = include_str!("../../../deploy/systemd/production.toml.example");
        let environment = [
            ("LARA_JWT__SECRET".to_owned(), "a".repeat(32)),
            ("LARA_MFA__ENCRYPTION_KEY".to_owned(), "11".repeat(32)),
            (
                "LARA_MYSQL__URL".to_owned(),
                "mysql://localhost/lara".into(),
            ),
            (
                "LARA_MONGODB__URI".to_owned(),
                "mongodb://localhost:27017".into(),
            ),
        ];
        let config = AppConfig::load_explicit_toml(overlay, environment).unwrap();
        let auxiliary = config
            .game_server
            .instances
            .iter()
            .find(|instance| instance.id == "dev-dm")
            .unwrap();
        let policy = config
            .effective_configuration_policy(auxiliary)
            .unwrap()
            .unwrap();
        assert_eq!(policy.fallback_encoding, "windows-1251");
        assert_eq!(policy.ignored_paths.len(), 2);
        assert!(policy.artifact_paths.is_empty());
    }

    #[test]
    fn validates_jwt_ttl_range() {
        assert_eq!(parse_jwt_ttl_seconds("60").unwrap(), 60);
        assert_eq!(parse_jwt_ttl_seconds("3600").unwrap(), 3_600);
        assert_eq!(parse_jwt_ttl_seconds("86400").unwrap(), 86_400);

        for invalid in ["", "not-a-number", "0", "59", "86401", "-1"] {
            assert!(matches!(
                parse_jwt_ttl_seconds(invalid),
                Err(ConfigError::InvalidJwtTtl)
            ));
        }
    }

    #[test]
    fn accepts_semantically_valid_configuration() {
        valid_config().validate().unwrap();
    }

    #[test]
    fn rejects_empty_required_values() {
        let mut cases: Vec<(&str, ConfigMutation)> = vec![
            (
                "jwt.secret",
                Box::new(|config| config.jwt.secret = super::super::model::SecretString::new(" ")),
            ),
            (
                "jwt.issuer",
                Box::new(|config| config.jwt.issuer = " ".into()),
            ),
            (
                "jwt.audience",
                Box::new(|config| config.jwt.audience = "".into()),
            ),
            (
                "mfa.encryption_key",
                Box::new(|config| {
                    config.mfa.encryption_key = super::super::model::SecretString::new(" ")
                }),
            ),
            (
                "mfa.issuer",
                Box::new(|config| config.mfa.issuer = "".into()),
            ),
            (
                "mysql.url",
                Box::new(|config| config.mysql.url = super::super::model::SecretString::new("")),
            ),
            (
                "mongodb.uri",
                Box::new(|config| config.mongodb.uri = super::super::model::SecretString::new(" ")),
            ),
            (
                "mongodb.database",
                Box::new(|config| config.mongodb.database = "".into()),
            ),
            (
                "game_server.storage.root",
                Box::new(|config| config.game_server.storage.root = "".into()),
            ),
        ];

        for (key, mutate) in cases.drain(..) {
            let mut config = valid_config();
            mutate(&mut config);

            assert!(matches!(
                config.validate(),
                Err(ConfigError::EmptyValue { key: invalid_key }) if invalid_key == key
            ));
        }
    }

    #[test]
    fn rejects_short_jwt_secret() {
        let mut config = valid_config();
        config.jwt.secret = super::super::model::SecretString::new("a".repeat(31));

        assert!(matches!(
            config.validate(),
            Err(ConfigError::JwtSecretTooShort { minimum: 32 })
        ));
    }

    #[test]
    fn validates_mfa_security_and_protocol_settings() {
        for invalid_key in [
            "11".repeat(31),
            "11".repeat(33),
            format!("{}zz", "11".repeat(31)),
        ] {
            let mut config = valid_config();
            config.mfa.encryption_key = super::super::model::SecretString::new(invalid_key);

            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidMfaEncryptionKey { expected_bytes: 32 })
            ));
        }

        for (key, mutate) in [
            (
                "mfa.challenge_ttl_seconds",
                Box::new(|config: &mut AppConfig| config.mfa.challenge_ttl_seconds = 59)
                    as ConfigMutation,
            ),
            (
                "mfa.enrollment_ttl_seconds",
                Box::new(|config: &mut AppConfig| config.mfa.enrollment_ttl_seconds = 3_601),
            ),
            (
                "mfa.max_verification_attempts",
                Box::new(|config: &mut AppConfig| config.mfa.max_verification_attempts = 0),
            ),
            (
                "mfa.totp_period_seconds",
                Box::new(|config: &mut AppConfig| config.mfa.totp_period_seconds = 14),
            ),
            (
                "mfa.allowed_clock_skew_steps",
                Box::new(|config: &mut AppConfig| config.mfa.allowed_clock_skew_steps = 3),
            ),
        ] {
            let mut config = valid_config();
            mutate(&mut config);
            assert!(matches!(
                config.validate(),
                Err(ConfigError::ValueOutOfRange { key: invalid_key, .. }) if invalid_key == key
            ));
        }

        for digits in [0, 5, 7, 9] {
            let mut config = valid_config();
            config.mfa.totp_digits = digits;
            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidMfaTotpDigits)
            ));
        }

        for digits in [6, 8] {
            let mut config = valid_config();
            config.mfa.totp_digits = digits;
            config.validate().unwrap();
        }
    }

    #[test]
    fn rejects_out_of_range_ttl_during_full_validation() {
        let mut config = valid_config();
        config.jwt.ttl_seconds = 59;

        assert!(matches!(config.validate(), Err(ConfigError::InvalidJwtTtl)));
    }

    #[test]
    fn rejects_invalid_file_storage_limits() {
        let cases: Vec<(&str, ConfigMutation)> = vec![
            (
                "game_server.storage.max_tree_depth",
                Box::new(|config| config.game_server.storage.max_tree_depth = 0),
            ),
            (
                "game_server.storage.max_tree_entries",
                Box::new(|config| config.game_server.storage.max_tree_entries = 1_000_001),
            ),
            (
                "game_server.storage.max_stream_size_bytes",
                Box::new(|config| config.game_server.storage.max_stream_size_bytes = 0),
            ),
        ];

        for (key, mutate) in cases {
            let mut config = valid_config();
            mutate(&mut config);

            assert!(matches!(
                config.validate(),
                Err(ConfigError::ValueOutOfRange { key: invalid_key, .. }) if invalid_key == key
            ));
        }
    }

    #[test]
    fn rejects_unsafe_configurator_directory() {
        for path in ["", ".", "../config", "scriptfiles/../config"] {
            let mut config = valid_config();
            config.configuration.files.configurator_directory = path.into();

            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidRelativePath {
                    key: "configuration.files.configurator_directory"
                })
            ));
        }
    }

    #[test]
    fn rejects_unsafe_maps_directory() {
        for path in ["", ".", "../maps", "scriptfiles/../maps", "C:/maps"] {
            let mut config = valid_config();
            config.maps.files.directory = path.into();

            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidRelativePath {
                    key: "maps.files.directory"
                })
            ));
        }
    }

    #[test]
    fn validates_maps_upload_limits_and_their_relationships() {
        let cases: Vec<(&str, ConfigMutation)> = vec![
            (
                "maps.upload.max_files_per_request",
                Box::new(|config| config.maps.upload.max_files_per_request = 0),
            ),
            (
                "maps.upload.max_files_per_request",
                Box::new(|config| config.maps.upload.max_files_per_request = 1_001),
            ),
            (
                "maps.upload.max_file_size_bytes",
                Box::new(|config| config.maps.upload.max_file_size_bytes = 0),
            ),
            (
                "maps.upload.max_file_size_bytes",
                Box::new(|config| {
                    config.maps.upload.max_file_size_bytes =
                        config.game_server.storage.max_stream_size_bytes + 1
                }),
            ),
            (
                "maps.upload.max_total_size_bytes",
                Box::new(|config| {
                    config.maps.upload.max_total_size_bytes =
                        config.maps.upload.max_file_size_bytes - 1
                }),
            ),
            (
                "maps.upload.max_total_size_bytes",
                Box::new(|config| {
                    config.maps.upload.max_total_size_bytes = MAX_MAP_BATCH_SIZE_BYTES + 1
                }),
            ),
        ];

        for (key, mutate) in cases {
            let mut config = valid_config();
            mutate(&mut config);

            assert!(matches!(
                config.validate(),
                Err(ConfigError::ValueOutOfRange { key: invalid_key, .. }) if invalid_key == key
            ));
        }
    }

    #[test]
    fn rejects_backup_storage_inside_the_managed_game_server_root() {
        for backup_directory in ["D:/servers/openmp", "D:/servers/openmp/backups"] {
            let mut config = valid_config();
            config.backups.storage.directory = backup_directory.into();

            assert!(matches!(
                config.validate(),
                Err(ConfigError::BackupDirectoryInsideGameServerRoot)
            ));
        }

        #[cfg(windows)]
        {
            let mut config = valid_config();
            config.backups.storage.directory = "D:/SERVERS/OPENMP/BACKUPS".into();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::BackupDirectoryInsideGameServerRoot)
            ));
        }

        let mut sibling = valid_config();
        sibling.backups.storage.directory = "D:/servers/openmp-backups".into();
        sibling.validate().unwrap();
    }

    #[test]
    fn validates_backup_compression_settings() {
        let mut invalid_gzip = valid_config();
        invalid_gzip.backups.storage.compression_level = 10;
        assert!(matches!(
            invalid_gzip.validate(),
            Err(ConfigError::InvalidBackupCompressionLevel {
                codec: "gzip",
                level: 10,
                ..
            })
        ));

        let mut invalid_none = valid_config();
        invalid_none.backups.storage.compression = BackupCompression::None;
        invalid_none.backups.storage.compression_level = 1;
        assert!(matches!(
            invalid_none.validate(),
            Err(ConfigError::InvalidBackupCompressionLevel {
                codec: "none",
                level: 1,
                ..
            })
        ));

        let mut valid_none = valid_config();
        valid_none.backups.storage.compression = BackupCompression::None;
        valid_none.backups.storage.compression_level = 0;
        valid_none.validate().unwrap();
    }

    #[test]
    fn validates_backup_retention_and_diff_limits() {
        let cases: Vec<(&str, ConfigMutation)> = vec![
            (
                "backups.storage.compression_threshold_bytes",
                Box::new(|config| {
                    config.backups.storage.compression_threshold_bytes =
                        config.game_server.storage.max_stream_size_bytes + 1
                }),
            ),
            (
                "backups.retention.lifetime_seconds",
                Box::new(|config| config.backups.retention.lifetime_seconds = 59),
            ),
            (
                "backups.retention.cleanup_interval_seconds",
                Box::new(|config| config.backups.retention.cleanup_interval_seconds = 0),
            ),
            (
                "backups.retention.cleanup_batch_size",
                Box::new(|config| config.backups.retention.cleanup_batch_size = 0),
            ),
            (
                "backups.retention.max_concurrent_deletions",
                Box::new(|config| config.backups.retention.max_concurrent_deletions = 65),
            ),
            (
                "backups.retention.operation_lease_seconds",
                Box::new(|config| config.backups.retention.operation_lease_seconds = 29),
            ),
            (
                "backups.retention.stale_preparation_seconds",
                Box::new(|config| {
                    config.backups.retention.stale_preparation_seconds =
                        config.backups.retention.operation_lease_seconds - 1
                }),
            ),
            (
                "backups.diff.max_input_size_bytes",
                Box::new(|config| config.backups.diff.max_input_size_bytes = 0),
            ),
            (
                "backups.diff.generation_timeout_ms",
                Box::new(|config| config.backups.diff.generation_timeout_ms = 60_001),
            ),
        ];

        for (key, mutate) in cases {
            let mut config = valid_config();
            mutate(&mut config);

            assert!(matches!(
                config.validate(),
                Err(ConfigError::ValueOutOfRange { key: invalid_key, .. }) if invalid_key == key
            ));
        }
    }

    #[test]
    fn validates_binary_file_rules_and_text_encoding() {
        for extensions in [
            vec![".cfg".into()],
            vec!["CFG".into()],
            vec!["amx".into(), "amx".into()],
        ] {
            let mut config = valid_config();
            config.configuration.files.binary_extensions = extensions;
            assert!(config.validate().is_err());
        }

        let mut no_binary_extensions = valid_config();
        no_binary_extensions
            .configuration
            .files
            .binary_extensions
            .clear();
        no_binary_extensions.validate().unwrap();

        for names in [
            vec!["../omp-server".into()],
            vec!["plugins/server".into()],
            vec!["omp-server".into(), "OMP-SERVER".into()],
        ] {
            let mut config = valid_config();
            config.configuration.files.binary_file_names = names;
            assert!(config.validate().is_err());
        }

        for paths in [vec!["../logs".into()], vec!["logs".into(), "LOGS".into()]] {
            let mut config = valid_config();
            config.configuration.files.ignored_paths = paths;
            assert!(config.validate().is_err());
        }

        let mut unsupported_encoding = valid_config();
        unsupported_encoding.configuration.files.fallback_encoding = "not-a-real-encoding".into();
        assert!(matches!(
            unsupported_encoding.validate(),
            Err(ConfigError::UnsupportedTextEncoding { .. })
        ));

        let mut valid_encoding = valid_config();
        valid_encoding.configuration.files.fallback_encoding = "utf-8".into();
        valid_encoding.validate().unwrap();
    }

    #[test]
    fn loads_all_legacy_environment_names_during_migration() {
        let defaults = include_str!("../../../config/default.toml");
        let legacy: Map<String, String> = Map::from([
            ("BIND_ADDRESS".into(), "0.0.0.0:8080".into()),
            ("MYSQL_DATABASE_URL".into(), "mysql://legacy/lara".into()),
            ("MONGODB_URI".into(), "mongodb://legacy:27017".into()),
            ("MONGODB_DATABASE".into(), "legacy-database".into()),
            (
                "LSRV_SECRET".into(),
                "legacy-secret-containing-32-bytes!".into(),
            ),
            ("JWT_ISSUER".into(), "legacy-issuer".into()),
            ("JWT_AUDIENCE".into(), "legacy-audience".into()),
            ("JWT_TTL_SECONDS".into(), "7200".into()),
        ]);
        let builder = ::config::Config::builder()
            .add_source(File::from_str(defaults, FileFormat::Toml))
            .set_override("mfa.encryption_key", "11".repeat(32))
            .unwrap();
        let builder =
            apply_legacy_environment_from(builder, &|name| legacy.get(name).cloned()).unwrap();

        let config = builder
            .build()
            .unwrap()
            .try_deserialize::<AppConfig>()
            .unwrap();

        config.validate().unwrap();
        assert_eq!(config.server.bind_address.to_string(), "0.0.0.0:8080");
        assert_eq!(config.mysql.url.expose_secret(), "mysql://legacy/lara");
        assert_eq!(config.mongodb.uri.expose_secret(), "mongodb://legacy:27017");
        assert_eq!(config.mongodb.database, "legacy-database");
        assert_eq!(config.jwt.issuer, "legacy-issuer");
        assert_eq!(config.jwt.audience, "legacy-audience");
        assert_eq!(config.jwt.ttl_seconds, 7_200);
    }

    #[test]
    fn modern_environment_names_take_priority_over_legacy_names() {
        let defaults = include_str!("../../../config/default.toml");
        let variables: Map<String, String> = Map::from([
            (
                "LSRV_SECRET".into(),
                "legacy-secret-containing-32-bytes!".into(),
            ),
            (
                "LARA_JWT__SECRET".into(),
                "modern-secret-containing-32-bytes!".into(),
            ),
            ("JWT_TTL_SECONDS".into(), "7200".into()),
            ("LARA_JWT__TTL_SECONDS".into(), "1800".into()),
            ("MYSQL_DATABASE_URL".into(), "mysql://legacy/lara".into()),
            ("LARA_MYSQL__URL".into(), "mysql://modern/lara".into()),
            ("MONGODB_URI".into(), "mongodb://legacy:27017".into()),
            ("LARA_MONGODB__URI".into(), "mongodb://modern:27017".into()),
        ]);
        let modern = Map::from([
            (
                "LARA_JWT__SECRET".into(),
                "modern-secret-containing-32-bytes!".into(),
            ),
            ("LARA_JWT__TTL_SECONDS".into(), "1800".into()),
            ("LARA_MYSQL__URL".into(), "mysql://modern/lara".into()),
            ("LARA_MONGODB__URI".into(), "mongodb://modern:27017".into()),
            ("LARA_MFA__ENCRYPTION_KEY".into(), "11".repeat(32)),
        ]);
        let builder =
            ::config::Config::builder().add_source(File::from_str(defaults, FileFormat::Toml));
        let builder = apply_legacy_environment_from(builder, &|name| variables.get(name).cloned())
            .unwrap()
            .add_source(lara_environment(Some(modern)));

        let config = builder
            .build()
            .unwrap()
            .try_deserialize::<AppConfig>()
            .unwrap();

        config.validate().unwrap();
        assert_eq!(
            config.jwt.secret.expose_secret(),
            "modern-secret-containing-32-bytes!"
        );
        assert_eq!(config.jwt.ttl_seconds, 1_800);
        assert_eq!(config.mysql.url.expose_secret(), "mysql://modern/lara");
        assert_eq!(config.mongodb.uri.expose_secret(), "mongodb://modern:27017");
    }

    #[test]
    fn committed_defaults_require_external_secrets() {
        let defaults = include_str!("../../../config/default.toml");

        let result = ::config::Config::builder()
            .add_source(File::from_str(defaults, FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize::<AppConfig>();

        assert!(result.is_err());
    }

    #[test]
    fn environment_overrides_file_values_using_nested_keys() {
        let base = r#"
            [server]
            bind_address = "127.0.0.1:3000"

            [jwt]
            secret = "file-secret"
            issuer = "lara"
            audience = "lara-api"
            ttl_seconds = 3600

            [mfa]
            issuer = "Lara"
            challenge_ttl_seconds = 300
            enrollment_ttl_seconds = 600
            max_verification_attempts = 5
            totp_period_seconds = 30
            totp_digits = 6
            allowed_clock_skew_steps = 1

            [mysql]
            url = "mysql://localhost/file"

            [mongodb]
            uri = "mongodb://localhost:27017"
            database = "lara"

            [game_server.storage]
            root = "D:/servers/openmp"
            max_tree_depth = 32
            max_tree_entries = 10000
            max_stream_size_bytes = 10485760

            [configuration.files]
            configurator_directory = "scriptfiles/config"
            binary_extensions = ["amx", "dff", "txd"]
            binary_file_names = ["omp-server", "samp03svr"]
            ignored_paths = ["logs"]
            fallback_encoding = "windows-1251"

            [maps.files]
            directory = "scriptfiles/maps"

            [maps.upload]
            max_files_per_request = 50
            max_file_size_bytes = 10485760
            max_total_size_bytes = 52428800

            [backups.storage]
            directory = "D:/backups"
            compression = "gzip"
            compression_level = 1
            compression_threshold_bytes = 1048576

            [backups.retention]
            lifetime_seconds = 1209600
            cleanup_interval_seconds = 3600
            cleanup_batch_size = 50
            max_concurrent_deletions = 8
            operation_lease_seconds = 300
            stale_preparation_seconds = 1800

            [backups.diff]
            enabled = true
            max_input_size_bytes = 10485760
            generation_timeout_ms = 5000
        "#;
        let environment = Map::from([
            ("LARA_SERVER__BIND_ADDRESS".into(), "0.0.0.0:8080".into()),
            (
                "LARA_JWT__SECRET".into(),
                "environment-secret-with-32-bytes!".into(),
            ),
            ("LARA_MFA__ENCRYPTION_KEY".into(), "11".repeat(32)),
            ("LARA_JWT__TTL_SECONDS".into(), "7200".into()),
            (
                "LARA_GAME_SERVER__STORAGE__MAX_TREE_DEPTH".into(),
                "64".into(),
            ),
            (
                "LARA_CONFIGURATION__FILES__BINARY_EXTENSIONS".into(),
                "amx,dff,txd,so".into(),
            ),
            (
                "LARA_CONFIGURATION__FILES__BINARY_FILE_NAMES".into(),
                "omp-server,samp03svr".into(),
            ),
            (
                "LARA_CONFIGURATION__FILES__IGNORED_PATHS".into(),
                "logs,scriptfiles/cache".into(),
            ),
            (
                "LARA_MAPS__FILES__DIRECTORY".into(),
                "scriptfiles/custom-maps".into(),
            ),
            (
                "LARA_MAPS__UPLOAD__MAX_FILES_PER_REQUEST".into(),
                "25".into(),
            ),
            (
                "LARA_MAPS__UPLOAD__MAX_FILE_SIZE_BYTES".into(),
                "5242880".into(),
            ),
            (
                "LARA_MAPS__UPLOAD__MAX_TOTAL_SIZE_BYTES".into(),
                "26214400".into(),
            ),
            (
                "LARA_BACKUPS__STORAGE__DIRECTORY".into(),
                "D:/custom-backups".into(),
            ),
            (
                "LARA_BACKUPS__RETENTION__LIFETIME_SECONDS".into(),
                "604800".into(),
            ),
            (
                "LARA_BACKUPS__DIFF__GENERATION_TIMEOUT_MS".into(),
                "2500".into(),
            ),
        ]);

        let config = ::config::Config::builder()
            .add_source(File::from_str(base, FileFormat::Toml))
            .add_source(lara_environment(Some(environment)))
            .build()
            .unwrap()
            .try_deserialize::<AppConfig>()
            .unwrap();

        config.validate().unwrap();

        assert_eq!(config.server.bind_address.to_string(), "0.0.0.0:8080");
        assert_eq!(
            config.jwt.secret.expose_secret(),
            "environment-secret-with-32-bytes!"
        );
        assert_eq!(config.jwt.ttl_seconds, 7_200);
        assert_eq!(config.game_server.storage.max_tree_depth, 64);
        assert_eq!(
            config.configuration.files.binary_extensions,
            vec!["amx", "dff", "txd", "so"]
        );
        assert_eq!(
            config.configuration.files.binary_file_names,
            vec!["omp-server", "samp03svr"]
        );
        assert_eq!(
            config.configuration.files.ignored_paths,
            vec![
                std::path::PathBuf::from("logs"),
                std::path::PathBuf::from("scriptfiles/cache")
            ]
        );
        assert_eq!(config.mysql.url.expose_secret(), "mysql://localhost/file");
        assert_eq!(
            config.maps.files.directory,
            std::path::PathBuf::from("scriptfiles/custom-maps")
        );
        assert_eq!(config.maps.upload.max_files_per_request, 25);
        assert_eq!(config.maps.upload.max_file_size_bytes, 5_242_880);
        assert_eq!(config.maps.upload.max_total_size_bytes, 26_214_400);
        assert_eq!(
            config.backups.storage.directory,
            std::path::PathBuf::from("D:/custom-backups")
        );
        assert_eq!(config.backups.retention.lifetime_seconds, 604_800);
        assert_eq!(config.backups.diff.generation_timeout_ms, 2_500);
    }

    #[test]
    fn explicit_file_overrides_defaults_before_environment_is_applied() {
        let defaults = include_str!("../../../config/default.toml");
        let overlay = r#"
            [server]
            bind_address = "0.0.0.0:8080"

            [jwt]
            issuer = "overlay-issuer"
            ttl_seconds = 1800

            [mongodb]
            database = "overlay-database"
        "#;
        let environment = Map::from([
            (
                "LARA_JWT__SECRET".into(),
                "environment-secret-with-32-bytes!".into(),
            ),
            ("LARA_JWT__ISSUER".into(), "environment-issuer".into()),
            ("LARA_MYSQL__URL".into(), "mysql://localhost/lara".into()),
            (
                "LARA_MONGODB__URI".into(),
                "mongodb://localhost:27017".into(),
            ),
            ("LARA_MFA__ENCRYPTION_KEY".into(), "11".repeat(32)),
        ]);

        let config = ::config::Config::builder()
            .add_source(File::from_str(defaults, FileFormat::Toml))
            .add_source(File::from_str(overlay, FileFormat::Toml))
            .add_source(lara_environment(Some(environment)))
            .build()
            .unwrap()
            .try_deserialize::<AppConfig>()
            .unwrap();

        config.validate().unwrap();
        assert_eq!(config.server.bind_address.to_string(), "0.0.0.0:8080");
        assert_eq!(config.jwt.issuer, "environment-issuer");
        assert_eq!(config.jwt.audience, "lara-api");
        assert_eq!(config.jwt.ttl_seconds, 1_800);
        assert_eq!(config.mongodb.database, "overlay-database");
    }

    #[test]
    fn committed_default_file_combines_with_environment_secrets() {
        let defaults = include_str!("../../../config/default.toml");
        let secrets = Map::from([
            (
                "LARA_JWT__SECRET".into(),
                "environment-secret-with-32-bytes!".into(),
            ),
            ("LARA_MYSQL__URL".into(), "mysql://localhost/lara".into()),
            (
                "LARA_MONGODB__URI".into(),
                "mongodb://localhost:27017".into(),
            ),
            ("LARA_MFA__ENCRYPTION_KEY".into(), "11".repeat(32)),
        ]);

        let config = ::config::Config::builder()
            .add_source(File::from_str(defaults, FileFormat::Toml))
            .add_source(lara_environment(Some(secrets)))
            .build()
            .unwrap()
            .try_deserialize::<AppConfig>()
            .unwrap();

        config.validate().unwrap();

        assert_eq!(config.server.bind_address.to_string(), "127.0.0.1:3000");
        assert_eq!(config.jwt.issuer, "lara");
        assert_eq!(config.jwt.audience, "lara-api");
        assert_eq!(config.jwt.ttl_seconds, 3_600);
        assert_eq!(config.mongodb.database, "lara");
        assert_eq!(
            config.jwt.secret.expose_secret(),
            "environment-secret-with-32-bytes!"
        );
    }

    #[test]
    fn packaged_production_overlay_merges_with_embedded_defaults() {
        let overlay = include_str!("../../../deploy/systemd/production.toml.example");
        let secrets = Map::from([
            (
                "LARA_JWT__SECRET".into(),
                "environment-secret-with-32-bytes!".into(),
            ),
            ("LARA_MFA__ENCRYPTION_KEY".into(), "11".repeat(32)),
            ("LARA_MYSQL__URL".into(), "mysql://localhost/lara".into()),
            (
                "LARA_MONGODB__URI".into(),
                "mongodb://localhost:27017".into(),
            ),
        ]);

        let config = ::config::Config::builder()
            .add_source(File::from_str(EMBEDDED_DEFAULT_CONFIG, FileFormat::Toml))
            .add_source(File::from_str(overlay, FileFormat::Toml))
            .add_source(lara_environment(Some(secrets)))
            .build()
            .unwrap()
            .try_deserialize::<AppConfig>()
            .unwrap();

        config.validate().unwrap();
        assert_eq!(config.game_server.instances.len(), 2);
        assert_eq!(config.game_server.instances[1].id, "dev-dm");
        assert_eq!(
            config.game_server.instances[1].management,
            Some(crate::shared::config::model::InstanceManagementConfig::Systemd)
        );
        assert_eq!(config.game_server.instances[1].systemd_observation, None);
        assert_eq!(
            config.backups.storage.directory,
            std::path::PathBuf::from("/var/lib/lara/backups")
        );
    }
}
