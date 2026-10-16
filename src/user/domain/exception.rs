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

#[derive(Debug, Error, PartialEq)]
pub enum HashedPasswordError {
    #[error("Password cannot be empty.")]
    EmptyPassword,

    #[error(
        "Password must be at least 8 characters long with a lowercase, an uppercase, a number and a special character"
    )]
    UnvalidPassword,

    #[error("Failed to hash password: {0}")]
    FailedHash(String),

    #[error("Failed to verify password: {0}")]
    FailedVerification(String),
}

#[derive(Debug, Error)]
pub enum UserError {
    #[error("INVALID_USERNAME")]
    InvalidUsername(String),

    #[error("INVALID_EMAIL: {0}")]
    InvalidEmail(String),

    #[error("INVALID_PASSWORD: {0}")]
    InvalidPassword(#[from] HashedPasswordError),
}
