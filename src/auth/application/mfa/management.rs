use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;

use crate::auth::{
    application::mfa::{
        ports::{
            MfaClock, MfaFactorRepository, MfaRepositoryError, MfaSecurityError,
            RecoveryCodeGenerator, RecoveryCodeHasher, TotpSecretCipher, TotpSecretGenerator,
            TotpVerifier,
        },
        verification::{MfaFactorVerificationService, MfaVerificationError},
    },
    domain::{
        mfa::{MfaEnrollmentId, MfaFactorStatus, RecoveryCode, TotpCode, TotpFactor},
        models::UserId,
    },
};

pub use crate::auth::application::mfa::verification::MfaProof;

const RECOVERY_CODE_COUNT: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaStatus {
    Disabled,
    EnrollmentPending,
    Enabled,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TotpEnrollment {
    pub enrollment_id: MfaEnrollmentId,
    pub secret: String,
    pub provisioning_uri: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct MfaActivation {
    /// Recovery codes are returned exactly once and are never persisted in
    /// plaintext. The caller must make this explicit to the user.
    pub recovery_codes: Vec<RecoveryCode>,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum MfaManagementError {
    #[error("MFA factor was not found")]
    NotFound,
    #[error("MFA factor conflicts with its current state")]
    Conflict,
    #[error("invalid or replayed MFA code")]
    InvalidCode,
    #[error("MFA dependency is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum MfaManagementConfigurationError {
    #[error("MFA issuer must not be blank")]
    EmptyIssuer,
    #[error("MFA enrollment TTL must be positive")]
    InvalidEnrollmentTtl,
    #[error("TOTP period must be positive and digits must be either 6 or 8")]
    InvalidTotpParameters,
}

/// Authenticated-user MFA lifecycle. HTTP authorization remains in the
/// presentation layer; this service always receives the user ID established
/// by the validated session and never trusts one supplied in a request body.
pub struct MfaManagementService {
    factors: Arc<dyn MfaFactorRepository>,
    secrets: Arc<dyn TotpSecretGenerator>,
    cipher: Arc<dyn TotpSecretCipher>,
    verifier: Arc<dyn TotpVerifier>,
    recovery_codes: Arc<dyn RecoveryCodeGenerator>,
    recovery_hasher: Arc<dyn RecoveryCodeHasher>,
    clock: Arc<dyn MfaClock>,
    factor_verification: MfaFactorVerificationService,
    issuer: String,
    enrollment_ttl: Duration,
    totp_period_seconds: u64,
    totp_digits: usize,
}

impl MfaManagementService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        factors: Arc<dyn MfaFactorRepository>,
        secrets: Arc<dyn TotpSecretGenerator>,
        cipher: Arc<dyn TotpSecretCipher>,
        verifier: Arc<dyn TotpVerifier>,
        recovery_codes: Arc<dyn RecoveryCodeGenerator>,
        recovery_hasher: Arc<dyn RecoveryCodeHasher>,
        clock: Arc<dyn MfaClock>,
        issuer: impl Into<String>,
        enrollment_ttl_seconds: u64,
        totp_period_seconds: u64,
        totp_digits: usize,
    ) -> Result<Self, MfaManagementConfigurationError> {
        let issuer = issuer.into();
        if issuer.trim().is_empty() {
            return Err(MfaManagementConfigurationError::EmptyIssuer);
        }
        let ttl_seconds = i64::try_from(enrollment_ttl_seconds)
            .ok()
            .filter(|seconds| *seconds > 0)
            .ok_or(MfaManagementConfigurationError::InvalidEnrollmentTtl)?;
        if totp_period_seconds == 0 || !matches!(totp_digits, 6 | 8) {
            return Err(MfaManagementConfigurationError::InvalidTotpParameters);
        }

        Ok(Self {
            factor_verification: MfaFactorVerificationService::new(
                Arc::clone(&factors),
                Arc::clone(&cipher),
                Arc::clone(&verifier),
                Arc::clone(&recovery_hasher),
                Arc::clone(&clock),
            ),
            factors,
            secrets,
            cipher,
            verifier,
            recovery_codes,
            recovery_hasher,
            clock,
            issuer,
            enrollment_ttl: Duration::seconds(ttl_seconds),
            totp_period_seconds,
            totp_digits,
        })
    }

    pub async fn status(&self, user_id: UserId) -> Result<MfaStatus, MfaManagementError> {
        let now = self.clock.now();
        let stored = self
            .factors
            .find_by_user_id(user_id)
            .await
            .map_err(map_repository_error)?;

        Ok(match stored {
            Some(stored) if stored.factor.status() == MfaFactorStatus::Active => MfaStatus::Enabled,
            Some(stored)
                if stored.factor.status() == MfaFactorStatus::Pending
                    && stored.pending_expires_at.is_some_and(|expiry| expiry > now) =>
            {
                MfaStatus::EnrollmentPending
            }
            Some(_) | None => MfaStatus::Disabled,
        })
    }

    pub async fn begin_enrollment(
        &self,
        user_id: UserId,
        account_name: &str,
    ) -> Result<TotpEnrollment, MfaManagementError> {
        let account_name = account_name.trim();
        if account_name.is_empty() {
            return Err(MfaManagementError::Conflict);
        }

        let now = self.clock.now();
        let expires_at = now
            .checked_add_signed(self.enrollment_ttl)
            .ok_or(MfaManagementError::Unavailable)?;
        let secret = self.secrets.generate().map_err(map_security_error)?;
        let encoded_secret = encode_base32(secret.as_bytes());
        let encrypted_secret = self
            .cipher
            .encrypt(user_id, &secret)
            .map_err(map_security_error)?;
        let enrollment_id = MfaEnrollmentId::new();
        let factor = TotpFactor::pending(
            user_id,
            enrollment_id,
            encrypted_secret,
            self.cipher.key_version(),
            now,
        )
        .map_err(|_| MfaManagementError::Unavailable)?;

        self.factors
            .replace_pending(&factor, expires_at)
            .await
            .map_err(map_repository_error)?;

        let label = format!(
            "{}:{}",
            percent_encode(&self.issuer),
            percent_encode(account_name)
        );
        let provisioning_uri = format!(
            "otpauth://totp/{label}?secret={encoded_secret}&issuer={}&algorithm=SHA1&digits={}&period={}",
            percent_encode(&self.issuer),
            self.totp_digits,
            self.totp_period_seconds
        );

        Ok(TotpEnrollment {
            enrollment_id,
            secret: encoded_secret,
            provisioning_uri,
            expires_at,
        })
    }

    pub async fn confirm_enrollment(
        &self,
        user_id: UserId,
        enrollment_id: MfaEnrollmentId,
        code: &TotpCode,
    ) -> Result<MfaActivation, MfaManagementError> {
        let now = self.clock.now();
        let stored = self
            .factors
            .find_by_user_id(user_id)
            .await
            .map_err(map_repository_error)?
            .ok_or(MfaManagementError::NotFound)?;

        if stored.factor.status() != MfaFactorStatus::Pending
            || stored.factor.enrollment_id() != enrollment_id
            || stored.pending_expires_at.is_none_or(|expiry| expiry <= now)
        {
            return Err(MfaManagementError::Conflict);
        }

        let secret = self
            .cipher
            .decrypt(user_id, stored.factor.encrypted_secret())
            .map_err(map_security_error)?;
        let accepted_step = self
            .verifier
            .verify(&secret, code, now)
            .map_err(map_security_error)?
            .ok_or(MfaManagementError::InvalidCode)?;

        let recovery_codes = self
            .recovery_codes
            .generate(RECOVERY_CODE_COUNT)
            .map_err(map_security_error)?;
        let mut hashes = Vec::with_capacity(recovery_codes.len());
        for recovery_code in &recovery_codes {
            hashes.push(
                self.recovery_hasher
                    .hash(recovery_code)
                    .await
                    .map_err(map_security_error)?,
            );
        }

        let activated = self
            .factors
            .activate_pending(user_id, enrollment_id, now, accepted_step, &hashes)
            .await
            .map_err(map_repository_error)?;
        if !activated.was_applied() {
            return Err(MfaManagementError::Conflict);
        }

        Ok(MfaActivation { recovery_codes })
    }

    pub async fn disable(
        &self,
        user_id: UserId,
        proof: MfaProof<'_>,
    ) -> Result<(), MfaManagementError> {
        self.factor_verification
            .verify(user_id, proof)
            .await
            .map_err(map_verification_error)?;
        let disabled = self
            .factors
            .disable_active(user_id, self.clock.now())
            .await
            .map_err(map_repository_error)?;
        if !disabled.was_applied() {
            return Err(MfaManagementError::Conflict);
        }
        Ok(())
    }

    pub async fn regenerate_recovery_codes(
        &self,
        user_id: UserId,
        proof: MfaProof<'_>,
    ) -> Result<Vec<RecoveryCode>, MfaManagementError> {
        self.factor_verification
            .verify(user_id, proof)
            .await
            .map_err(map_verification_error)?;
        let recovery_codes = self
            .recovery_codes
            .generate(RECOVERY_CODE_COUNT)
            .map_err(map_security_error)?;
        let mut hashes = Vec::with_capacity(recovery_codes.len());
        for recovery_code in &recovery_codes {
            hashes.push(
                self.recovery_hasher
                    .hash(recovery_code)
                    .await
                    .map_err(map_security_error)?,
            );
        }

        let replaced = self
            .factors
            .replace_recovery_codes(user_id, &hashes)
            .await
            .map_err(map_repository_error)?;
        if !replaced.was_applied() {
            return Err(MfaManagementError::Conflict);
        }
        Ok(recovery_codes)
    }
}

fn map_repository_error(error: MfaRepositoryError) -> MfaManagementError {
    match error {
        MfaRepositoryError::Conflict => MfaManagementError::Conflict,
        MfaRepositoryError::InvalidData { .. } | MfaRepositoryError::Unavailable { .. } => {
            tracing::error!(error = %error, error_debug = ?error, "MFA repository operation failed");
            MfaManagementError::Unavailable
        }
    }
}

fn map_security_error(error: MfaSecurityError) -> MfaManagementError {
    tracing::error!(error = %error, error_debug = ?error, "MFA security operation failed");
    MfaManagementError::Unavailable
}

fn map_verification_error(error: MfaVerificationError) -> MfaManagementError {
    match error {
        MfaVerificationError::NotFound => MfaManagementError::NotFound,
        MfaVerificationError::InvalidCode => MfaManagementError::InvalidCode,
        MfaVerificationError::Unavailable => MfaManagementError::Unavailable,
    }
}

fn encode_base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;

    for &byte in bytes {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((accumulator >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(ALPHABET[((accumulator << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_encoding_matches_rfc_4648_without_padding() {
        assert_eq!(encode_base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn provisioning_components_are_percent_encoded() {
        assert_eq!(percent_encode("Lara SAMP/MP"), "Lara%20SAMP%2FMP");
        assert_eq!(
            percent_encode("user+tag@example.com"),
            "user%2Btag%40example.com"
        );
    }
}
