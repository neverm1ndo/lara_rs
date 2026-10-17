use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use super::models::UserId;

const MIN_TOTP_DIGITS: usize = 6;
const MAX_TOTP_DIGITS: usize = 8;
const MAX_RECOVERY_CODE_LENGTH: usize = 128;

macro_rules! uuid_identifier {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self)
            }
        }
    };
}

uuid_identifier!(MfaEnrollmentId);
uuid_identifier!(MfaLoginChallengeId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MfaFactorKind {
    Totp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MfaFactorStatus {
    Pending,
    Active,
    Disabled,
}

/// Authentication strength recorded by a server-side session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthenticationMethod {
    Password,
    PasswordTotp,
    PasswordRecoveryCode,
}

/// Opaque authenticated-encryption envelope. Ciphertext layout belongs to the
/// infrastructure adapter and is deliberately invisible to the domain.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedTotpSecret(Vec<u8>);

impl EncryptedTotpSecret {
    pub fn new(value: Vec<u8>) -> Result<Self, InvalidMfaValue> {
        if value.is_empty() {
            return Err(InvalidMfaValue::EmptyEncryptedSecret);
        }
        Ok(Self(value))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for EncryptedTotpSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncryptedTotpSecret([REDACTED])")
    }
}

/// User-supplied TOTP value. The configured verifier decides whether six or
/// eight digits are expected; this type rejects every other representation.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpCode(String);

impl TotpCode {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidMfaValue> {
        let value = value.into();
        if !(MIN_TOTP_DIGITS..=MAX_TOTP_DIGITS).contains(&value.len())
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(InvalidMfaValue::TotpCode);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TotpCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TotpCode([REDACTED])")
    }
}

/// Plaintext recovery code exists only at the API boundary and during
/// verification. Persistence adapters must store a one-way hash instead.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryCode(String);

impl RecoveryCode {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidMfaValue> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_RECOVERY_CODE_LENGTH
            || value.trim() != value
            || value.chars().any(char::is_whitespace)
        {
            return Err(InvalidMfaValue::RecoveryCode);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryCode([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationAttempts {
    remaining: u16,
}

impl VerificationAttempts {
    pub fn new(limit: u16) -> Result<Self, InvalidMfaValue> {
        if limit == 0 {
            return Err(InvalidMfaValue::VerificationAttempts);
        }
        Ok(Self { remaining: limit })
    }

    /// Used when rebuilding a challenge after failures; zero is a valid
    /// exhausted state.
    pub const fn from_remaining(remaining: u16) -> Self {
        Self { remaining }
    }

    pub const fn remaining(self) -> u16 {
        self.remaining
    }

    pub const fn is_exhausted(self) -> bool {
        self.remaining == 0
    }

    pub fn record_failure(&mut self) {
        self.remaining = self.remaining.saturating_sub(1);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpFactor {
    user_id: UserId,
    enrollment_id: MfaEnrollmentId,
    encrypted_secret: EncryptedTotpSecret,
    key_version: u32,
    status: MfaFactorStatus,
    created_at: DateTime<Utc>,
    enabled_at: Option<DateTime<Utc>>,
    last_accepted_step: Option<u64>,
}

impl TotpFactor {
    pub fn pending(
        user_id: UserId,
        enrollment_id: MfaEnrollmentId,
        encrypted_secret: EncryptedTotpSecret,
        key_version: u32,
        created_at: DateTime<Utc>,
    ) -> Result<Self, InvalidMfaValue> {
        if key_version == 0 {
            return Err(InvalidMfaValue::EncryptionKeyVersion);
        }

        Ok(Self {
            user_id,
            enrollment_id,
            encrypted_secret,
            key_version,
            status: MfaFactorStatus::Pending,
            created_at,
            enabled_at: None,
            last_accepted_step: None,
        })
    }

    pub const fn kind(&self) -> MfaFactorKind {
        MfaFactorKind::Totp
    }

    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    pub const fn enrollment_id(&self) -> MfaEnrollmentId {
        self.enrollment_id
    }

    pub const fn encrypted_secret(&self) -> &EncryptedTotpSecret {
        &self.encrypted_secret
    }

    pub const fn key_version(&self) -> u32 {
        self.key_version
    }

    pub const fn status(&self) -> MfaFactorStatus {
        self.status
    }

    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub const fn enabled_at(&self) -> Option<DateTime<Utc>> {
        self.enabled_at
    }

    pub const fn last_accepted_step(&self) -> Option<u64> {
        self.last_accepted_step
    }

    pub fn activate(&mut self, now: DateTime<Utc>) -> Result<(), InvalidMfaTransition> {
        if self.status != MfaFactorStatus::Pending || now < self.created_at {
            return Err(InvalidMfaTransition::Activate);
        }
        self.status = MfaFactorStatus::Active;
        self.enabled_at = Some(now);
        Ok(())
    }

    pub fn disable(&mut self) -> Result<(), InvalidMfaTransition> {
        if self.status != MfaFactorStatus::Active {
            return Err(InvalidMfaTransition::Disable);
        }
        self.status = MfaFactorStatus::Disabled;
        Ok(())
    }

    /// Records an accepted time step in memory. Persistence must perform the
    /// equivalent comparison atomically to prevent concurrent replay.
    pub fn accept_step(&mut self, step: u64) -> Result<(), InvalidMfaTransition> {
        if self.status != MfaFactorStatus::Active
            || self
                .last_accepted_step
                .is_some_and(|accepted| step <= accepted)
        {
            return Err(InvalidMfaTransition::TotpReplay);
        }
        self.last_accepted_step = Some(step);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MfaLoginChallenge {
    id: MfaLoginChallengeId,
    user_id: UserId,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    attempts: VerificationAttempts,
    consumed_at: Option<DateTime<Utc>>,
}

impl MfaLoginChallenge {
    pub fn new(
        id: MfaLoginChallengeId,
        user_id: UserId,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        attempts: VerificationAttempts,
    ) -> Result<Self, InvalidMfaValue> {
        if expires_at <= created_at {
            return Err(InvalidMfaValue::ChallengeExpiration);
        }
        if attempts.is_exhausted() {
            return Err(InvalidMfaValue::VerificationAttempts);
        }

        Ok(Self {
            id,
            user_id,
            created_at,
            expires_at,
            attempts,
            consumed_at: None,
        })
    }

    pub const fn id(&self) -> MfaLoginChallengeId {
        self.id
    }

    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn attempts(&self) -> VerificationAttempts {
        self.attempts
    }

    pub const fn consumed_at(&self) -> Option<DateTime<Utc>> {
        self.consumed_at
    }

    pub fn is_available(&self, now: DateTime<Utc>) -> bool {
        self.consumed_at.is_none() && !self.attempts.is_exhausted() && self.expires_at > now
    }

    pub fn record_failure(&mut self) {
        self.attempts.record_failure();
    }

    pub fn consume(&mut self, now: DateTime<Utc>) -> Result<(), InvalidMfaTransition> {
        if !self.is_available(now) || now < self.created_at {
            return Err(InvalidMfaTransition::ConsumeChallenge);
        }
        self.consumed_at = Some(now);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidMfaValue {
    #[error("encrypted TOTP secret must not be empty")]
    EmptyEncryptedSecret,
    #[error("encryption key version must be positive")]
    EncryptionKeyVersion,
    #[error("TOTP code must contain six to eight ASCII digits")]
    TotpCode,
    #[error("recovery code has an invalid format")]
    RecoveryCode,
    #[error("verification attempt limit must be positive")]
    VerificationAttempts,
    #[error("MFA challenge expiration must be after its creation")]
    ChallengeExpiration,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidMfaTransition {
    #[error("only a pending TOTP factor can be activated")]
    Activate,
    #[error("only an active TOTP factor can be disabled")]
    Disable,
    #[error("TOTP time step was already accepted or the factor is not active")]
    TotpReplay,
    #[error("MFA login challenge is expired, exhausted, or already consumed")]
    ConsumeChallenge,
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn timestamp(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).unwrap()
    }

    #[test]
    fn identifiers_round_trip_as_uuid_strings() {
        let enrollment = MfaEnrollmentId::new();
        let challenge = MfaLoginChallengeId::new();

        assert_eq!(enrollment.to_string().parse(), Ok(enrollment));
        assert_eq!(challenge.to_string().parse(), Ok(challenge));
    }

    #[test]
    fn sensitive_values_validate_input_and_redact_debug_output() {
        let secret = EncryptedTotpSecret::new(vec![1, 2, 3]).unwrap();
        let totp = TotpCode::new("012345").unwrap();
        let recovery = RecoveryCode::new("ABCD-EFGH").unwrap();

        assert_eq!(format!("{secret:?}"), "EncryptedTotpSecret([REDACTED])");
        assert_eq!(format!("{totp:?}"), "TotpCode([REDACTED])");
        assert_eq!(format!("{recovery:?}"), "RecoveryCode([REDACTED])");
        assert_eq!(TotpCode::new("12345"), Err(InvalidMfaValue::TotpCode));
        assert_eq!(TotpCode::new("12345a"), Err(InvalidMfaValue::TotpCode));
        assert_eq!(
            RecoveryCode::new(" ABCD-EFGH"),
            Err(InvalidMfaValue::RecoveryCode)
        );
    }

    #[test]
    fn factor_has_explicit_lifecycle_and_rejects_totp_replay() {
        let created_at = timestamp(1_000);
        let mut factor = TotpFactor::pending(
            UserId::new(42).unwrap(),
            MfaEnrollmentId::new(),
            EncryptedTotpSecret::new(vec![1]).unwrap(),
            1,
            created_at,
        )
        .unwrap();

        assert_eq!(factor.kind(), MfaFactorKind::Totp);
        assert_eq!(factor.status(), MfaFactorStatus::Pending);
        assert_eq!(
            factor.accept_step(10),
            Err(InvalidMfaTransition::TotpReplay)
        );

        factor.activate(created_at + Duration::seconds(1)).unwrap();
        factor.accept_step(10).unwrap();
        assert_eq!(
            factor.accept_step(10),
            Err(InvalidMfaTransition::TotpReplay)
        );
        assert_eq!(factor.accept_step(9), Err(InvalidMfaTransition::TotpReplay));
        factor.accept_step(11).unwrap();
        factor.disable().unwrap();
        assert_eq!(factor.status(), MfaFactorStatus::Disabled);
    }

    #[test]
    fn challenge_expires_exhausts_and_can_only_be_consumed_once() {
        let created_at = timestamp(1_000);
        let expires_at = created_at + Duration::minutes(5);
        let attempts = VerificationAttempts::new(2).unwrap();
        let mut challenge = MfaLoginChallenge::new(
            MfaLoginChallengeId::new(),
            UserId::new(42).unwrap(),
            created_at,
            expires_at,
            attempts,
        )
        .unwrap();

        challenge.record_failure();
        assert!(challenge.is_available(created_at));
        challenge.record_failure();
        assert!(!challenge.is_available(created_at));

        let mut consumable = MfaLoginChallenge::new(
            MfaLoginChallengeId::new(),
            UserId::new(42).unwrap(),
            created_at,
            expires_at,
            VerificationAttempts::new(1).unwrap(),
        )
        .unwrap();
        consumable.consume(created_at).unwrap();
        assert_eq!(
            consumable.consume(created_at),
            Err(InvalidMfaTransition::ConsumeChallenge)
        );
        assert!(!consumable.is_available(expires_at));
    }
}
