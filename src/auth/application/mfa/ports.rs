use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::auth::domain::{
    mfa::{
        EncryptedTotpSecret, MfaChallengeToken, MfaChallengeTokenHash, MfaEnrollmentId,
        MfaLoginChallenge, MfaLoginChallengeId, RecoveryCode, RecoveryCodeHash, TotpCode,
        TotpFactor, TotpSecret,
    },
    models::UserId,
};

pub type MfaRepositoryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, MfaRepositoryError>> + Send + 'a>>;
pub type MfaSecurityFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, MfaSecurityError>> + Send + 'a>>;

/// Persistence representation used by MFA application services. Pending
/// expiry and recovery hashes are kept outside the core factor lifecycle but
/// remain private to the authentication bounded context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTotpFactor {
    pub factor: TotpFactor,
    pub pending_expires_at: Option<DateTime<Utc>>,
    pub recovery_code_hashes: Vec<RecoveryCodeHash>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicMfaUpdate {
    Applied,
    Rejected,
}

impl AtomicMfaUpdate {
    pub const fn was_applied(self) -> bool {
        matches!(self, Self::Applied)
    }
}

/// Factor persistence contract. Every mutating operation is a single
/// compare-and-set operation in the adapter; implementations must not model
/// these methods as an unprotected read followed by a write.
pub trait MfaFactorRepository: Send + Sync {
    fn find_by_user_id<'a>(
        &'a self,
        user_id: UserId,
    ) -> MfaRepositoryFuture<'a, Option<StoredTotpFactor>>;

    /// Replaces any previous pending enrollment for the user. An active
    /// factor must make this operation return `Conflict`.
    fn replace_pending<'a>(
        &'a self,
        factor: &'a TotpFactor,
        pending_expires_at: DateTime<Utc>,
    ) -> MfaRepositoryFuture<'a, ()>;

    /// Activates exactly the matching non-expired pending enrollment and
    /// installs freshly generated recovery-code hashes.
    fn activate_pending<'a>(
        &'a self,
        user_id: UserId,
        enrollment_id: MfaEnrollmentId,
        now: DateTime<Utc>,
        accepted_step: u64,
        recovery_code_hashes: &'a [RecoveryCodeHash],
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate>;

    fn disable_active<'a>(
        &'a self,
        user_id: UserId,
        disabled_at: DateTime<Utc>,
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate>;

    /// Accepts `step` only for an active factor when it is strictly greater
    /// than the persisted last accepted step. This is the replay-protection
    /// compare-and-set boundary.
    fn accept_totp_step<'a>(
        &'a self,
        user_id: UserId,
        step: u64,
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate>;

    /// Removes exactly one matching hash from an active factor.
    fn consume_recovery_code<'a>(
        &'a self,
        user_id: UserId,
        hash: &'a RecoveryCodeHash,
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate>;

    fn replace_recovery_codes<'a>(
        &'a self,
        user_id: UserId,
        hashes: &'a [RecoveryCodeHash],
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate>;
}

/// Challenge persistence contract. Expiration, remaining attempts and
/// consumed state must be predicates of each atomic update, independently of
/// eventual MongoDB TTL cleanup.
pub trait MfaChallengeRepository: Send + Sync {
    fn create<'a>(
        &'a self,
        challenge: &'a MfaLoginChallenge,
        token_hash: MfaChallengeTokenHash,
    ) -> MfaRepositoryFuture<'a, ()>;

    fn find_available_by_token_hash<'a>(
        &'a self,
        token_hash: MfaChallengeTokenHash,
        now: DateTime<Utc>,
    ) -> MfaRepositoryFuture<'a, Option<MfaLoginChallenge>>;

    fn record_failed_attempt<'a>(
        &'a self,
        challenge_id: MfaLoginChallengeId,
        now: DateTime<Utc>,
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate>;

    fn consume<'a>(
        &'a self,
        challenge_id: MfaLoginChallengeId,
        now: DateTime<Utc>,
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate>;
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum MfaRepositoryError {
    #[error("MFA record already exists or conflicts with its current state")]
    Conflict,
    #[error("MFA persistence contains invalid data: {message}")]
    InvalidData { message: String },
    #[error("MFA repository is unavailable: {message}")]
    Unavailable { message: String },
}

/// Generates cryptographically random TOTP seeds.
pub trait TotpSecretGenerator: Send + Sync {
    fn generate(&self) -> Result<TotpSecret, MfaSecurityError>;
}

/// Encrypts TOTP seeds before persistence and decrypts them only for bounded
/// enrollment/verification operations.
pub trait TotpSecretCipher: Send + Sync {
    fn encrypt(
        &self,
        user_id: UserId,
        secret: &TotpSecret,
    ) -> Result<EncryptedTotpSecret, MfaSecurityError>;

    fn decrypt(
        &self,
        user_id: UserId,
        secret: &EncryptedTotpSecret,
    ) -> Result<TotpSecret, MfaSecurityError>;

    fn key_version(&self) -> u32;
}

/// Returns the accepted RFC 6238 time step, or `None` for an invalid code.
/// Returning the step lets the repository enforce replay protection
/// atomically instead of trusting an in-memory factor snapshot.
pub trait TotpVerifier: Send + Sync {
    fn verify(
        &self,
        secret: &TotpSecret,
        code: &TotpCode,
        now: DateTime<Utc>,
    ) -> Result<Option<u64>, MfaSecurityError>;
}

pub trait MfaChallengeTokenGenerator: Send + Sync {
    fn generate(&self) -> Result<MfaChallengeToken, MfaSecurityError>;
}

/// Produces a deterministic fixed-size digest for indexed challenge lookup.
/// The raw bearer token is never persisted.
pub trait MfaChallengeTokenHasher: Send + Sync {
    fn hash(&self, token: &MfaChallengeToken) -> MfaChallengeTokenHash;
}

pub trait RecoveryCodeGenerator: Send + Sync {
    fn generate(&self, count: usize) -> Result<Vec<RecoveryCode>, MfaSecurityError>;
}

pub trait RecoveryCodeHasher: Send + Sync {
    fn hash<'a>(&'a self, code: &'a RecoveryCode) -> MfaSecurityFuture<'a, RecoveryCodeHash>;

    fn verify<'a>(
        &'a self,
        code: &'a RecoveryCode,
        hash: &'a RecoveryCodeHash,
    ) -> MfaSecurityFuture<'a, bool>;
}

/// Injectable wall clock used by MFA use cases and deterministic tests.
pub trait MfaClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum MfaSecurityError {
    #[error("failed to generate secure MFA material")]
    Generation,
    #[error("failed to encrypt TOTP secret")]
    Encryption,
    #[error("failed to decrypt TOTP secret")]
    Decryption,
    #[error("failed to calculate or verify TOTP")]
    Totp,
    #[error("failed to hash or verify recovery code")]
    RecoveryCodeHash,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_update_has_an_explicit_success_signal() {
        assert!(AtomicMfaUpdate::Applied.was_applied());
        assert!(!AtomicMfaUpdate::Rejected.was_applied());
    }

    #[test]
    fn repository_errors_do_not_contain_secret_values_by_design() {
        assert_eq!(
            MfaRepositoryError::Conflict.to_string(),
            "MFA record already exists or conflicts with its current state"
        );
        assert_eq!(
            MfaSecurityError::Decryption.to_string(),
            "failed to decrypt TOTP secret"
        );
    }
}
