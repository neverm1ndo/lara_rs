use std::sync::Arc;

use thiserror::Error;

use crate::auth::{
    application::mfa::ports::{
        MfaClock, MfaFactorRepository, MfaRepositoryError, MfaSecurityError, RecoveryCodeHasher,
        TotpSecretCipher, TotpVerifier,
    },
    domain::{
        mfa::{AuthenticationMethod, MfaFactorStatus, RecoveryCode, TotpCode},
        models::UserId,
    },
};

pub enum MfaProof<'a> {
    Totp(&'a TotpCode),
    RecoveryCode(&'a RecoveryCode),
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum MfaVerificationError {
    #[error("active MFA factor was not found")]
    NotFound,
    #[error("invalid or replayed MFA code")]
    InvalidCode,
    #[error("MFA verification dependency is unavailable")]
    Unavailable,
}

pub struct MfaFactorVerificationService {
    factors: Arc<dyn MfaFactorRepository>,
    cipher: Arc<dyn TotpSecretCipher>,
    verifier: Arc<dyn TotpVerifier>,
    recovery_hasher: Arc<dyn RecoveryCodeHasher>,
    clock: Arc<dyn MfaClock>,
}

impl MfaFactorVerificationService {
    pub fn new(
        factors: Arc<dyn MfaFactorRepository>,
        cipher: Arc<dyn TotpSecretCipher>,
        verifier: Arc<dyn TotpVerifier>,
        recovery_hasher: Arc<dyn RecoveryCodeHasher>,
        clock: Arc<dyn MfaClock>,
    ) -> Self {
        Self {
            factors,
            cipher,
            verifier,
            recovery_hasher,
            clock,
        }
    }

    pub async fn verify(
        &self,
        user_id: UserId,
        proof: MfaProof<'_>,
    ) -> Result<AuthenticationMethod, MfaVerificationError> {
        let stored = self
            .factors
            .find_by_user_id(user_id)
            .await
            .map_err(map_repository_error)?
            .filter(|stored| stored.factor.status() == MfaFactorStatus::Active)
            .ok_or(MfaVerificationError::NotFound)?;

        match proof {
            MfaProof::Totp(code) => {
                let secret = self
                    .cipher
                    .decrypt(user_id, stored.factor.encrypted_secret())
                    .map_err(map_security_error)?;
                let step = self
                    .verifier
                    .verify(&secret, code, self.clock.now())
                    .map_err(map_security_error)?
                    .ok_or(MfaVerificationError::InvalidCode)?;
                let accepted = self
                    .factors
                    .accept_totp_step(user_id, step)
                    .await
                    .map_err(map_repository_error)?;
                if !accepted.was_applied() {
                    return Err(MfaVerificationError::InvalidCode);
                }
                Ok(AuthenticationMethod::PasswordTotp)
            }
            MfaProof::RecoveryCode(code) => {
                // Verify every stored hash to avoid leaking its position via
                // response time. Only the first match is consumed.
                let mut matched = None;
                for hash in &stored.recovery_code_hashes {
                    if self
                        .recovery_hasher
                        .verify(code, hash)
                        .await
                        .map_err(map_security_error)?
                        && matched.is_none()
                    {
                        matched = Some(hash);
                    }
                }
                let hash = matched.ok_or(MfaVerificationError::InvalidCode)?;
                let consumed = self
                    .factors
                    .consume_recovery_code(user_id, hash)
                    .await
                    .map_err(map_repository_error)?;
                if !consumed.was_applied() {
                    return Err(MfaVerificationError::InvalidCode);
                }
                Ok(AuthenticationMethod::PasswordRecoveryCode)
            }
        }
    }
}

fn map_repository_error(error: MfaRepositoryError) -> MfaVerificationError {
    match error {
        MfaRepositoryError::Conflict => MfaVerificationError::InvalidCode,
        MfaRepositoryError::InvalidData { .. } | MfaRepositoryError::Unavailable { .. } => {
            tracing::error!(error = %error, error_debug = ?error, "MFA verification repository failed");
            MfaVerificationError::Unavailable
        }
    }
}

fn map_security_error(error: MfaSecurityError) -> MfaVerificationError {
    tracing::error!(error = %error, error_debug = ?error, "MFA verification primitive failed");
    MfaVerificationError::Unavailable
}
