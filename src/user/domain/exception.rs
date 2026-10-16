use thiserror::Error;

use crate::shared::user_role::UserRole;

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("user ID must be a positive integer")]
pub struct InvalidUserId;

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidUserProfile {
    #[error("username must not be empty")]
    EmptyUsername,
    #[error("user must have at least one workspace permission")]
    EmptyPermissions,
    #[error("main group {0:?} is not present in user permissions")]
    MainGroupNotGranted(UserRole),
    #[error("permission {0:?} is duplicated")]
    DuplicatePermission(UserRole),
}
