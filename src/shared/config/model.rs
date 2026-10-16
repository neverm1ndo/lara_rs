use std::{fmt, net::SocketAddr, path::PathBuf};

use serde::Deserialize;

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    #[cfg(test)]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub jwt: JwtConfig,
    pub mysql: MySqlConfig,
    pub mongodb: MongoConfig,
    pub game_server: GameServerConfig,
    pub configuration: ConfigurationConfig,
    pub maps: MapsConfig,
    pub backups: BackupsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub bind_address: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub secret: SecretString,
    pub issuer: String,
    pub audience: String,
    pub ttl_seconds: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MySqlConfig {
    pub url: SecretString,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MongoConfig {
    pub uri: SecretString,
    pub database: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GameServerConfig {
    pub storage: FileStorageConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileStorageConfig {
    pub root: PathBuf,
    pub max_tree_depth: usize,
    pub max_tree_entries: usize,
    pub max_stream_size_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigurationConfig {
    pub files: ConfigurationFilesConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigurationFilesConfig {
    pub configurator_directory: PathBuf,
    pub binary_extensions: Vec<String>,
    pub binary_file_names: Vec<String>,
    pub ignored_paths: Vec<PathBuf>,
    pub fallback_encoding: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MapsConfig {
    pub files: MapsFilesConfig,
    pub upload: MapsUploadConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MapsFilesConfig {
    /// Directory relative to `game_server.storage.root` that contains the map
    /// tree managed by the maps bounded context.
    pub directory: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MapsUploadConfig {
    pub max_files_per_request: usize,
    pub max_file_size_bytes: u64,
    pub max_total_size_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackupsConfig {
    pub storage: BackupStorageConfig,
    pub retention: BackupRetentionConfig,
    pub diff: BackupDiffConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackupStorageConfig {
    /// Private backup directory. Relative paths are resolved from the server
    /// process working directory, never from the game-server root.
    pub directory: PathBuf,
    pub compression: BackupCompression,
    pub compression_level: u32,
    pub compression_threshold_bytes: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackupCompression {
    None,
    Gzip,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackupRetentionConfig {
    pub lifetime_seconds: u64,
    pub cleanup_interval_seconds: u64,
    pub cleanup_batch_size: usize,
    pub max_concurrent_deletions: usize,
    pub operation_lease_seconds: u64,
    pub stale_preparation_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackupDiffConfig {
    pub enabled: bool,
    pub max_input_size_bytes: u64,
    pub generation_timeout_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_secrets_recursively() {
        let config = AppConfig {
            server: ServerConfig {
                bind_address: "127.0.0.1:3000".parse().unwrap(),
            },
            jwt: JwtConfig {
                secret: SecretString::new("jwt-secret"),
                issuer: "lara".into(),
                audience: "lara-api".into(),
                ttl_seconds: 3_600,
            },
            mysql: MySqlConfig {
                url: SecretString::new("mysql://user:password@localhost/lara"),
            },
            mongodb: MongoConfig {
                uri: SecretString::new("mongodb://user:password@localhost/lara"),
                database: "lara".into(),
            },
            game_server: GameServerConfig {
                storage: FileStorageConfig {
                    root: "D:/servers/openmp".into(),
                    max_tree_depth: 32,
                    max_tree_entries: 10_000,
                    max_stream_size_bytes: 10 * 1024 * 1024,
                },
            },
            configuration: ConfigurationConfig {
                files: ConfigurationFilesConfig {
                    configurator_directory: "scriptfiles/config".into(),
                    binary_extensions: vec!["amx".into(), "dff".into(), "txd".into()],
                    binary_file_names: vec!["omp-server".into(), "samp03svr".into()],
                    ignored_paths: vec!["logs".into(), "scriptfiles/cache".into()],
                    fallback_encoding: "windows-1251".into(),
                },
            },
            maps: MapsConfig {
                files: MapsFilesConfig {
                    directory: "scriptfiles/maps".into(),
                },
                upload: MapsUploadConfig {
                    max_files_per_request: 50,
                    max_file_size_bytes: 10 * 1024 * 1024,
                    max_total_size_bytes: 50 * 1024 * 1024,
                },
            },
            backups: BackupsConfig {
                storage: BackupStorageConfig {
                    directory: "D:/backups".into(),
                    compression: BackupCompression::Gzip,
                    compression_level: 1,
                    compression_threshold_bytes: 1024 * 1024,
                },
                retention: BackupRetentionConfig {
                    lifetime_seconds: 14 * 24 * 60 * 60,
                    cleanup_interval_seconds: 60 * 60,
                    cleanup_batch_size: 50,
                    max_concurrent_deletions: 8,
                    operation_lease_seconds: 300,
                    stale_preparation_seconds: 1800,
                },
                diff: BackupDiffConfig {
                    enabled: true,
                    max_input_size_bytes: 10 * 1024 * 1024,
                    generation_timeout_ms: 5000,
                },
            },
        };

        let debug = format!("{config:?}");

        assert!(!debug.contains("jwt-secret"));
        assert!(!debug.contains("user:password"));
        assert_eq!(debug.matches("[REDACTED]").count(), 3);
    }

    #[test]
    fn deserializes_nested_configuration_model() {
        let config: AppConfig = serde_json::from_value(serde_json::json!({
            "server": { "bind_address": "0.0.0.0:8080" },
            "jwt": {
                "secret": "jwt-secret",
                "issuer": "lara",
                "audience": "lara-api",
                "ttl_seconds": 3600
            },
            "mysql": { "url": "mysql://localhost/lara" },
            "mongodb": {
                "uri": "mongodb://localhost:27017",
                "database": "lara"
            },
            "game_server": {
                "storage": {
                    "root": "D:/servers/openmp",
                    "max_tree_depth": 32,
                    "max_tree_entries": 10000,
                    "max_stream_size_bytes": 10485760
                }
            },
            "configuration": {
                "files": {
                    "configurator_directory": "scriptfiles/config",
                    "binary_extensions": ["amx", "dff", "txd"],
                    "binary_file_names": ["omp-server", "samp03svr"],
                    "ignored_paths": ["logs", "scriptfiles/cache"],
                    "fallback_encoding": "windows-1251"
                }
            },
            "maps": {
                "files": {
                    "directory": "scriptfiles/maps"
                },
                "upload": {
                    "max_files_per_request": 50,
                    "max_file_size_bytes": 10485760,
                    "max_total_size_bytes": 52428800
                }
            },
            "backups": {
                "storage": {
                    "directory": "D:/backups",
                    "compression": "gzip",
                    "compression_level": 1,
                    "compression_threshold_bytes": 1048576
                },
                "retention": {
                    "lifetime_seconds": 1209600,
                    "cleanup_interval_seconds": 3600,
                    "cleanup_batch_size": 50,
                    "max_concurrent_deletions": 8,
                    "operation_lease_seconds": 300,
                    "stale_preparation_seconds": 1800
                },
                "diff": {
                    "enabled": true,
                    "max_input_size_bytes": 10485760,
                    "generation_timeout_ms": 5000
                }
            }
        }))
        .unwrap();

        assert_eq!(config.server.bind_address.to_string(), "0.0.0.0:8080");
        assert_eq!(config.jwt.secret.expose_secret(), "jwt-secret");
        assert_eq!(config.jwt.ttl_seconds, 3_600);
        assert_eq!(config.mysql.url.expose_secret(), "mysql://localhost/lara");
        assert_eq!(config.mongodb.database, "lara");
        assert_eq!(
            config.game_server.storage.root,
            PathBuf::from("D:/servers/openmp")
        );
        assert_eq!(config.game_server.storage.max_tree_entries, 10_000);
        assert_eq!(
            config.configuration.files.configurator_directory,
            PathBuf::from("scriptfiles/config")
        );
        assert_eq!(
            config.configuration.files.binary_extensions,
            vec!["amx", "dff", "txd"]
        );
        assert_eq!(
            config.configuration.files.binary_file_names,
            vec!["omp-server", "samp03svr"]
        );
        assert_eq!(
            config.configuration.files.ignored_paths,
            vec![PathBuf::from("logs"), PathBuf::from("scriptfiles/cache")]
        );
        assert_eq!(
            config.maps.files.directory,
            PathBuf::from("scriptfiles/maps")
        );
        assert_eq!(config.maps.upload.max_files_per_request, 50);
        assert_eq!(config.maps.upload.max_file_size_bytes, 10_485_760);
        assert_eq!(config.maps.upload.max_total_size_bytes, 52_428_800);
        assert_eq!(
            config.backups.storage.directory,
            PathBuf::from("D:/backups")
        );
        assert_eq!(config.backups.storage.compression, BackupCompression::Gzip);
        assert_eq!(config.backups.retention.lifetime_seconds, 1_209_600);
        assert!(config.backups.diff.enabled);
    }
}
