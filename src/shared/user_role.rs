use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Shared authorization vocabulary used by the auth and user contexts.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum UserRole {
    Challenger = 9,
    Developer = 10,
    Admin = 11,
    Mapper = 12,
    Configurator = 13,
    Backuper = 14,
}

impl UserRole {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    pub const fn grants_workspace_access(self) -> bool {
        matches!(
            self,
            Self::Challenger
                | Self::Developer
                | Self::Admin
                | Self::Mapper
                | Self::Configurator
                | Self::Backuper
        )
    }
}

impl TryFrom<i32> for UserRole {
    type Error = InvalidUserRole;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            9 => Ok(Self::Challenger),
            10 => Ok(Self::Developer),
            11 => Ok(Self::Admin),
            12 => Ok(Self::Mapper),
            13 => Ok(Self::Configurator),
            14 => Ok(Self::Backuper),
            value => Err(InvalidUserRole(i64::from(value))),
        }
    }
}

impl TryFrom<u32> for UserRole {
    type Error = InvalidUserRole;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            9 => Ok(Self::Challenger),
            10 => Ok(Self::Developer),
            11 => Ok(Self::Admin),
            12 => Ok(Self::Mapper),
            13 => Ok(Self::Configurator),
            14 => Ok(Self::Backuper),
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
