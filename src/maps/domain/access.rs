use thiserror::Error;

use crate::shared::user_role::UserRole;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapAccessLevel {
    Developer,
    Mapper,
}

/// Authorization decision for the maps bounded context. Both access levels
/// receive the same filesystem capability; the level is retained for audit
/// events and future domain rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapAccess {
    level: MapAccessLevel,
}

impl MapAccess {
    pub fn authorize(
        main_group: UserRole,
        permissions: &[UserRole],
    ) -> Result<Self, MapAccessError> {
        let has_role = |required| main_group == required || permissions.contains(&required);

        if has_role(UserRole::Developer) {
            return Ok(Self {
                level: MapAccessLevel::Developer,
            });
        }
        if has_role(UserRole::Mapper) {
            return Ok(Self {
                level: MapAccessLevel::Mapper,
            });
        }

        Err(MapAccessError::Forbidden)
    }

    pub fn level(self) -> MapAccessLevel {
        self.level
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum MapAccessError {
    #[error("map file access requires the developer or mapper role")]
    Forbidden,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorizes_developer_and_mapper_from_main_group_or_permissions() {
        let cases = [
            (UserRole::Developer, vec![], MapAccessLevel::Developer),
            (
                UserRole::Challenger,
                vec![UserRole::Developer],
                MapAccessLevel::Developer,
            ),
            (UserRole::Mapper, vec![], MapAccessLevel::Mapper),
            (
                UserRole::Challenger,
                vec![UserRole::Mapper],
                MapAccessLevel::Mapper,
            ),
        ];

        for (main_group, permissions, expected) in cases {
            assert_eq!(
                MapAccess::authorize(main_group, &permissions)
                    .unwrap()
                    .level(),
                expected
            );
        }
    }

    #[test]
    fn developer_membership_takes_precedence_for_a_dual_role_user() {
        let access = MapAccess::authorize(UserRole::Mapper, &[UserRole::Developer]).unwrap();

        assert_eq!(access.level(), MapAccessLevel::Developer);
    }

    #[test]
    fn rejects_other_workspace_roles() {
        for role in [
            UserRole::Challenger,
            UserRole::Admin,
            UserRole::Configurator,
            UserRole::Backuper,
        ] {
            assert_eq!(
                MapAccess::authorize(role, &[]),
                Err(MapAccessError::Forbidden)
            );
        }
    }
}
