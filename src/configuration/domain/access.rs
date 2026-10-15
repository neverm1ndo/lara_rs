use thiserror::Error;

use crate::shared::{file_storage::path::RelativeStoragePath, user_role::UserRole};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationAccessLevel {
    Developer,
    Configurator,
}

/// Authorized filesystem view for one request. Paths received from the client
/// are always relative to this root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationAccess {
    level: ConfigurationAccessLevel,
    storage_root: RelativeStoragePath,
}

impl ConfigurationAccess {
    pub fn authorize(
        main_group: UserRole,
        permissions: &[UserRole],
        configurator_directory: &RelativeStoragePath,
    ) -> Result<Self, ConfigurationAccessError> {
        let has_role = |required| main_group == required || permissions.contains(&required);

        if has_role(UserRole::DEVELOPER) {
            return Ok(Self {
                level: ConfigurationAccessLevel::Developer,
                storage_root: RelativeStoragePath::root(),
            });
        }

        if has_role(UserRole::CONFIGURATOR) {
            return Ok(Self {
                level: ConfigurationAccessLevel::Configurator,
                storage_root: configurator_directory.clone(),
            });
        }

        Err(ConfigurationAccessError::Forbidden)
    }

    pub fn level(&self) -> ConfigurationAccessLevel {
        self.level
    }

    pub fn storage_root(&self) -> &RelativeStoragePath {
        &self.storage_root
    }

    /// Maps a client-visible path into the game-server root namespace. This is
    /// used for global ignored-path checks before accessing a scoped storage.
    pub fn server_path(&self, client_path: &RelativeStoragePath) -> RelativeStoragePath {
        self.storage_root.join_path(client_path)
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ConfigurationAccessError {
    #[error("configuration file access requires the developer or configurator role")]
    Forbidden,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configurator_directory() -> RelativeStoragePath {
        RelativeStoragePath::new("scriptfiles/config").unwrap()
    }

    #[test]
    fn developer_receives_the_full_server_capability() {
        let access =
            ConfigurationAccess::authorize(UserRole::DEVELOPER, &[], &configurator_directory())
                .unwrap();

        assert_eq!(access.level(), ConfigurationAccessLevel::Developer);
        assert!(access.storage_root().is_root());
        assert_eq!(
            access.server_path(&RelativeStoragePath::new("server.cfg").unwrap()),
            RelativeStoragePath::new("server.cfg").unwrap()
        );
    }

    #[test]
    fn configurator_receives_only_the_configured_subtree() {
        let access = ConfigurationAccess::authorize(
            UserRole::CHALLENGER,
            &[UserRole::CONFIGURATOR],
            &configurator_directory(),
        )
        .unwrap();

        assert_eq!(access.level(), ConfigurationAccessLevel::Configurator);
        assert_eq!(access.storage_root(), &configurator_directory());
        assert_eq!(
            access.server_path(&RelativeStoragePath::new("modes/race.cfg").unwrap()),
            RelativeStoragePath::new("scriptfiles/config/modes/race.cfg").unwrap()
        );
    }

    #[test]
    fn developer_membership_takes_precedence_over_configurator_membership() {
        let access = ConfigurationAccess::authorize(
            UserRole::CONFIGURATOR,
            &[UserRole::DEVELOPER],
            &configurator_directory(),
        )
        .unwrap();

        assert_eq!(access.level(), ConfigurationAccessLevel::Developer);
        assert!(access.storage_root().is_root());
    }

    #[test]
    fn other_workspace_roles_are_not_implicitly_authorized() {
        for role in [
            UserRole::CHALLENGER,
            UserRole::ADMIN,
            UserRole::MAPPER,
            UserRole::BACKUPER,
        ] {
            assert_eq!(
                ConfigurationAccess::authorize(role, &[], &configurator_directory()),
                Err(ConfigurationAccessError::Forbidden)
            );
        }
    }
}
