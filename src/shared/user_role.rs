use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Shared authorization vocabulary used by the auth and user contexts.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum UserRole {
    CHALLENGER = 9,
    DEVELOPER = 10,
    ADMIN = 11,
    MAPPER = 12,
    CONFIGURATOR = 13,
    BACKUPER = 14,
}

impl UserRole {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    pub const fn grants_workspace_access(self) -> bool {
        matches!(
            self,
            Self::CHALLENGER
                | Self::DEVELOPER
                | Self::ADMIN
                | Self::MAPPER
                | Self::CONFIGURATOR
                | Self::BACKUPER
        )
    }
}

impl TryFrom<i32> for UserRole {
    type Error = InvalidUserRole;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            9 => Ok(Self::CHALLENGER),
            10 => Ok(Self::DEVELOPER),
            11 => Ok(Self::ADMIN),
            12 => Ok(Self::MAPPER),
            13 => Ok(Self::CONFIGURATOR),
            14 => Ok(Self::BACKUPER),
            value => Err(InvalidUserRole(i64::from(value))),
        }
    }
}

impl TryFrom<u32> for UserRole {
    type Error = InvalidUserRole;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            9 => Ok(Self::CHALLENGER),
            10 => Ok(Self::DEVELOPER),
            11 => Ok(Self::ADMIN),
            12 => Ok(Self::MAPPER),
            13 => Ok(Self::CONFIGURATOR),
            14 => Ok(Self::BACKUPER),
            value => Err(InvalidUserRole(i64::from(value))),
        }
    }
}

impl From<UserRole> for i32 {
    fn from(role: UserRole) -> Self {
        role.as_i32()
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("unknown user role: {0}")]
pub struct InvalidUserRole(pub i64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_all_workspace_group_ids() {
        for id in 9..=14 {
            let role = UserRole::try_from(id).unwrap();
            assert_eq!(role.as_i32(), id);
            assert!(role.grants_workspace_access());
        }
    }

    #[test]
    fn rejects_non_workspace_group_ids() {
        assert_eq!(UserRole::try_from(8), Err(InvalidUserRole(8)));
        assert_eq!(UserRole::try_from(15), Err(InvalidUserRole(15)));
    }
}
