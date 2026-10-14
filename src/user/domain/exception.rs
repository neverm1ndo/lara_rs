use thiserror::Error;

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
