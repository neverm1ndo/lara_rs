use std::collections::HashSet;

use thiserror::Error;

use crate::shared::file_storage::path::{RelativeStoragePath, StorageFileName};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BinaryExtension(String);

impl BinaryExtension {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidConfigurationFilePolicy> {
        let value = value.into();
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(InvalidConfigurationFilePolicy::BinaryExtension(value));
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationFileKind {
    Text,
    Binary,
}

/// Domain rules shared by tree, read and mutation use cases. Ignored paths are
/// expressed relative to the complete game-server root, not a user's scope.
#[derive(Debug, Clone)]
pub struct ConfigurationFilePolicy {
    binary_extensions: HashSet<String>,
    binary_file_names: HashSet<String>,
    ignored_paths: Vec<RelativeStoragePath>,
}

impl ConfigurationFilePolicy {
    pub fn new(
        binary_extensions: impl IntoIterator<Item = BinaryExtension>,
        binary_file_names: impl IntoIterator<Item = StorageFileName>,
        ignored_paths: impl IntoIterator<Item = RelativeStoragePath>,
    ) -> Result<Self, InvalidConfigurationFilePolicy> {
        let mut extension_set = HashSet::new();
        for extension in binary_extensions {
            if !extension_set.insert(extension.0) {
                return Err(InvalidConfigurationFilePolicy::DuplicateBinaryExtension);
            }
        }

        let mut name_set = HashSet::new();
        for name in binary_file_names {
            if !name_set.insert(name.as_str().to_ascii_lowercase()) {
                return Err(InvalidConfigurationFilePolicy::DuplicateBinaryFileName);
            }
        }

        let mut ignored = Vec::new();
        for path in ignored_paths {
            if path.is_root() {
                return Err(InvalidConfigurationFilePolicy::IgnoredRoot);
            }
            if ignored
                .iter()
                .any(|existing: &RelativeStoragePath| existing.is_within_case_insensitive(&path))
            {
                return Err(InvalidConfigurationFilePolicy::DuplicateIgnoredPath);
            }
            ignored.push(path);
        }

        Ok(Self {
            binary_extensions: extension_set,
            binary_file_names: name_set,
            ignored_paths: ignored,
        })
    }

    pub fn classify(&self, path: &RelativeStoragePath) -> ConfigurationFileKind {
        let Some(file_name) = path.file_name() else {
            return ConfigurationFileKind::Text;
        };
        let normalized_name = file_name.to_ascii_lowercase();

        if self.binary_file_names.contains(&normalized_name) {
            return ConfigurationFileKind::Binary;
        }

        let extension = normalized_name.rsplit_once('.').map(|(_, value)| value);
        if extension.is_some_and(|value| self.binary_extensions.contains(value)) {
            ConfigurationFileKind::Binary
        } else {
            ConfigurationFileKind::Text
        }
    }

    pub fn is_ignored(&self, server_path: &RelativeStoragePath) -> bool {
        self.ignored_paths
            .iter()
            .any(|ignored| server_path.is_within_case_insensitive(ignored))
    }

    pub fn ensure_visible(
        &self,
        server_path: &RelativeStoragePath,
    ) -> Result<(), InvalidConfigurationFilePolicy> {
        if self.is_ignored(server_path) {
            Err(InvalidConfigurationFilePolicy::IgnoredPath)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum InvalidConfigurationFilePolicy {
    #[error("binary extension is invalid: {0}")]
    BinaryExtension(String),
    #[error("binary extensions must be unique")]
    DuplicateBinaryExtension,
    #[error("binary file names must be unique ignoring ASCII case")]
    DuplicateBinaryFileName,
    #[error("the complete storage root cannot be ignored")]
    IgnoredRoot,
    #[error("ignored paths must not be duplicated")]
    DuplicateIgnoredPath,
    #[error("the requested path belongs to an ignored subtree")]
    IgnoredPath,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::domain::ConfigurationAccess;
    use crate::shared::user_role::UserRole;

    fn path(value: &str) -> RelativeStoragePath {
        RelativeStoragePath::new(value).unwrap()
    }

    fn policy() -> ConfigurationFilePolicy {
        ConfigurationFilePolicy::new(
            [
                BinaryExtension::new("amx").unwrap(),
                BinaryExtension::new("txd").unwrap(),
            ],
            [StorageFileName::new("omp-server").unwrap()],
            [path("logs"), path("scriptfiles/config/private")],
        )
        .unwrap()
    }

    #[test]
    fn validates_binary_extensions() {
        assert_eq!(BinaryExtension::new("amx").unwrap().as_str(), "amx");
        for invalid in ["", ".amx", "AMX", "so-1"] {
            assert!(BinaryExtension::new(invalid).is_err());
        }
    }

    #[test]
    fn classifies_configured_names_and_extensions_case_insensitively() {
        let policy = policy();

        for binary in ["gamemodes/RACE.AMX", "models/car.TXD", "OMP-SERVER"] {
            assert_eq!(
                policy.classify(&path(binary)),
                ConfigurationFileKind::Binary
            );
        }
        for text in ["server.cfg", "README", "gamemodes/source.pwn", ".env"] {
            assert_eq!(policy.classify(&path(text)), ConfigurationFileKind::Text);
        }
    }

    #[test]
    fn hides_complete_subtrees_without_matching_similar_prefixes() {
        let policy = policy();

        assert!(policy.is_ignored(&path("LOGS")));
        assert!(policy.is_ignored(&path("logs/server.log")));
        assert!(policy.is_ignored(&path("scriptfiles/config/private/secrets.cfg")));
        assert!(!policy.is_ignored(&path("logs-old/server.log")));
        assert!(!policy.is_ignored(&path("scriptfiles/config/public/server.cfg")));
    }

    #[test]
    fn ignored_rules_are_checked_after_mapping_the_user_scope() {
        let policy = policy();
        let configurator_root = path("scriptfiles/config");
        let access =
            ConfigurationAccess::authorize(UserRole::Configurator, &[], &configurator_root)
                .unwrap();

        assert!(policy.is_ignored(&access.server_path(&path("private/secrets.cfg"))));
        assert!(!policy.is_ignored(&access.server_path(&path("logs/server.log"))));
    }

    #[test]
    fn rejects_duplicate_or_dangerous_policy_entries() {
        assert!(matches!(
            ConfigurationFilePolicy::new(
                [
                    BinaryExtension::new("amx").unwrap(),
                    BinaryExtension::new("amx").unwrap()
                ],
                [],
                [],
            ),
            Err(InvalidConfigurationFilePolicy::DuplicateBinaryExtension)
        ));

        assert!(matches!(
            ConfigurationFilePolicy::new(
                [],
                [
                    StorageFileName::new("omp-server").unwrap(),
                    StorageFileName::new("OMP-SERVER").unwrap(),
                ],
                [],
            ),
            Err(InvalidConfigurationFilePolicy::DuplicateBinaryFileName)
        ));

        assert!(matches!(
            ConfigurationFilePolicy::new([], [], [RelativeStoragePath::root()]),
            Err(InvalidConfigurationFilePolicy::IgnoredRoot)
        ));
    }
}
