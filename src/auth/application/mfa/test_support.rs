use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use chrono::{DateTime, Utc};

use crate::auth::{
    application::mfa::ports::{
        AtomicMfaUpdate, MfaChallengeRepository, MfaChallengeTokenGenerator,
        MfaChallengeTokenHasher, MfaClock, MfaFactorRepository, MfaRepositoryError,
        MfaRepositoryFuture, MfaSecurityError, MfaSecurityFuture, RecoveryCodeGenerator,
        RecoveryCodeHasher, StoredTotpFactor, TotpSecretCipher, TotpSecretGenerator, TotpVerifier,
    },
    domain::{
        mfa::{
            EncryptedTotpSecret, MfaChallengeToken, MfaChallengeTokenHash, MfaEnrollmentId,
            MfaFactorStatus, MfaLoginChallenge, MfaLoginChallengeId, RecoveryCode,
            RecoveryCodeHash, TotpCode, TotpFactor, TotpSecret,
        },
        models::UserId,
    },
};

type ChallengeRecord = (MfaChallengeTokenHash, MfaLoginChallenge);

#[derive(Default)]
pub struct MemoryMfaRepository {
    factors: Mutex<HashMap<i64, StoredTotpFactor>>,
    challenges: Mutex<Vec<ChallengeRecord>>,
}

impl MemoryMfaRepository {
    pub fn factor(&self, user_id: UserId) -> Option<StoredTotpFactor> {
        self.factors.lock().unwrap().get(&user_id.get()).cloned()
    }

    pub fn insert_factor(&self, factor: StoredTotpFactor) {
        self.factors
            .lock()
            .unwrap()
            .insert(factor.factor.user_id().get(), factor);
    }
}

impl MfaFactorRepository for MemoryMfaRepository {
    fn find_by_user_id<'a>(
        &'a self,
        user_id: UserId,
    ) -> MfaRepositoryFuture<'a, Option<StoredTotpFactor>> {
        Box::pin(async move { Ok(self.factor(user_id)) })
    }

    fn replace_pending<'a>(
        &'a self,
        factor: &'a TotpFactor,
        pending_expires_at: DateTime<Utc>,
    ) -> MfaRepositoryFuture<'a, ()> {
        Box::pin(async move {
            let mut factors = self.factors.lock().unwrap();
            if factors
                .get(&factor.user_id().get())
                .is_some_and(|stored| stored.factor.status() == MfaFactorStatus::Active)
            {
                return Err(MfaRepositoryError::Conflict);
            }
            factors.insert(
                factor.user_id().get(),
                StoredTotpFactor {
                    factor: factor.clone(),
                    pending_expires_at: Some(pending_expires_at),
                    recovery_code_hashes: Vec::new(),
                },
            );
            Ok(())
        })
    }

    fn activate_pending<'a>(
        &'a self,
        user_id: UserId,
        enrollment_id: MfaEnrollmentId,
        now: DateTime<Utc>,
        accepted_step: u64,
        recovery_code_hashes: &'a [RecoveryCodeHash],
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
        Box::pin(async move {
            let mut factors = self.factors.lock().unwrap();
            let Some(stored) = factors.get_mut(&user_id.get()) else {
                return Ok(AtomicMfaUpdate::Rejected);
            };
            if stored.factor.status() != MfaFactorStatus::Pending
                || stored.factor.enrollment_id() != enrollment_id
                || stored.pending_expires_at.is_none_or(|expiry| expiry <= now)
            {
                return Ok(AtomicMfaUpdate::Rejected);
            }
            stored
                .factor
                .activate(now)
                .map_err(|error| MfaRepositoryError::InvalidData {
                    message: error.to_string(),
                })?;
            stored.factor.accept_step(accepted_step).map_err(|error| {
                MfaRepositoryError::InvalidData {
                    message: error.to_string(),
                }
            })?;
            stored.pending_expires_at = None;
            stored.recovery_code_hashes = recovery_code_hashes.to_vec();
            Ok(AtomicMfaUpdate::Applied)
        })
    }

    fn disable_active<'a>(
        &'a self,
        user_id: UserId,
        _disabled_at: DateTime<Utc>,
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
        Box::pin(async move {
            let mut factors = self.factors.lock().unwrap();
            let Some(stored) = factors.get_mut(&user_id.get()) else {
                return Ok(AtomicMfaUpdate::Rejected);
            };
            if stored.factor.disable().is_err() {
                return Ok(AtomicMfaUpdate::Rejected);
            }
            Ok(AtomicMfaUpdate::Applied)
        })
    }

    fn accept_totp_step<'a>(
        &'a self,
        user_id: UserId,
        step: u64,
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
        Box::pin(async move {
            let mut factors = self.factors.lock().unwrap();
            let Some(stored) = factors.get_mut(&user_id.get()) else {
                return Ok(AtomicMfaUpdate::Rejected);
            };
            Ok(if stored.factor.accept_step(step).is_ok() {
                AtomicMfaUpdate::Applied
            } else {
                AtomicMfaUpdate::Rejected
            })
        })
    }

    fn consume_recovery_code<'a>(
        &'a self,
        user_id: UserId,
        hash: &'a RecoveryCodeHash,
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
        Box::pin(async move {
            let mut factors = self.factors.lock().unwrap();
            let Some(stored) = factors.get_mut(&user_id.get()) else {
                return Ok(AtomicMfaUpdate::Rejected);
            };
            if stored.factor.status() != MfaFactorStatus::Active {
                return Ok(AtomicMfaUpdate::Rejected);
            }
            let original_len = stored.recovery_code_hashes.len();
            stored.recovery_code_hashes.retain(|stored| stored != hash);
            Ok(if stored.recovery_code_hashes.len() < original_len {
                AtomicMfaUpdate::Applied
            } else {
                AtomicMfaUpdate::Rejected
            })
        })
    }

    fn replace_recovery_codes<'a>(
        &'a self,
        user_id: UserId,
        hashes: &'a [RecoveryCodeHash],
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
        Box::pin(async move {
            let mut factors = self.factors.lock().unwrap();
            let Some(stored) = factors.get_mut(&user_id.get()) else {
                return Ok(AtomicMfaUpdate::Rejected);
            };
            if stored.factor.status() != MfaFactorStatus::Active {
                return Ok(AtomicMfaUpdate::Rejected);
            }
            stored.recovery_code_hashes = hashes.to_vec();
            Ok(AtomicMfaUpdate::Applied)
        })
    }
}

impl MfaChallengeRepository for MemoryMfaRepository {
    fn create<'a>(
        &'a self,
        challenge: &'a MfaLoginChallenge,
        token_hash: MfaChallengeTokenHash,
    ) -> MfaRepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.challenges
                .lock()
                .unwrap()
                .push((token_hash, challenge.clone()));
            Ok(())
        })
    }

    fn find_available_by_token_hash<'a>(
        &'a self,
        token_hash: MfaChallengeTokenHash,
        now: DateTime<Utc>,
    ) -> MfaRepositoryFuture<'a, Option<MfaLoginChallenge>> {
        Box::pin(async move {
            Ok(self
                .challenges
                .lock()
                .unwrap()
                .iter()
                .find(|(hash, challenge)| *hash == token_hash && challenge.is_available(now))
                .map(|(_, challenge)| challenge.clone()))
        })
    }

    fn record_failed_attempt<'a>(
        &'a self,
        challenge_id: MfaLoginChallengeId,
        now: DateTime<Utc>,
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
        Box::pin(async move {
            let mut challenges = self.challenges.lock().unwrap();
            let Some((_, challenge)) = challenges.iter_mut().find(|(_, challenge)| {
                challenge.id() == challenge_id && challenge.is_available(now)
            }) else {
                return Ok(AtomicMfaUpdate::Rejected);
            };
            challenge.record_failure();
            Ok(AtomicMfaUpdate::Applied)
        })
    }

    fn consume<'a>(
        &'a self,
        challenge_id: MfaLoginChallengeId,
        now: DateTime<Utc>,
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
        Box::pin(async move {
            let mut challenges = self.challenges.lock().unwrap();
            let Some((_, challenge)) = challenges.iter_mut().find(|(_, challenge)| {
                challenge.id() == challenge_id && challenge.is_available(now)
            }) else {
                return Ok(AtomicMfaUpdate::Rejected);
            };
            challenge
                .consume(now)
                .map_err(|error| MfaRepositoryError::InvalidData {
                    message: error.to_string(),
                })?;
            Ok(AtomicMfaUpdate::Applied)
        })
    }
}

#[derive(Clone)]
pub struct FixedClock(pub Arc<Mutex<DateTime<Utc>>>);

impl FixedClock {
    pub fn at(now: DateTime<Utc>) -> Self {
        Self(Arc::new(Mutex::new(now)))
    }
}

impl MfaClock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

#[derive(Default)]
pub struct TestSecurity {
    recovery_generation: AtomicUsize,
}

impl TotpSecretGenerator for TestSecurity {
    fn generate(&self) -> Result<TotpSecret, MfaSecurityError> {
        TotpSecret::new(b"test-secret".to_vec()).map_err(|_| MfaSecurityError::Generation)
    }
}

impl TotpSecretCipher for TestSecurity {
    fn encrypt(
        &self,
        _user_id: UserId,
        secret: &TotpSecret,
    ) -> Result<EncryptedTotpSecret, MfaSecurityError> {
        EncryptedTotpSecret::new(secret.as_bytes().to_vec())
            .map_err(|_| MfaSecurityError::Encryption)
    }

    fn decrypt(
        &self,
        _user_id: UserId,
        secret: &EncryptedTotpSecret,
    ) -> Result<TotpSecret, MfaSecurityError> {
        TotpSecret::new(secret.as_bytes().to_vec()).map_err(|_| MfaSecurityError::Decryption)
    }

    fn key_version(&self) -> u32 {
        1
    }
}

impl TotpVerifier for TestSecurity {
    fn verify(
        &self,
        _secret: &TotpSecret,
        code: &TotpCode,
        now: DateTime<Utc>,
    ) -> Result<Option<u64>, MfaSecurityError> {
        let step = u64::try_from(now.timestamp()).map_err(|_| MfaSecurityError::Totp)? / 30;
        Ok((code.as_str() == "123456").then_some(step))
    }
}

impl MfaChallengeTokenGenerator for TestSecurity {
    fn generate(&self) -> Result<MfaChallengeToken, MfaSecurityError> {
        MfaChallengeToken::new("test-challenge").map_err(|_| MfaSecurityError::Generation)
    }
}

impl MfaChallengeTokenHasher for TestSecurity {
    fn hash(&self, token: &MfaChallengeToken) -> MfaChallengeTokenHash {
        let mut hash = [0_u8; 32];
        for (index, byte) in token.as_str().bytes().enumerate() {
            let position = index % hash.len();
            hash[position] ^= byte;
        }
        MfaChallengeTokenHash::new(hash)
    }
}

impl RecoveryCodeGenerator for TestSecurity {
    fn generate(&self, count: usize) -> Result<Vec<RecoveryCode>, MfaSecurityError> {
        let generation = self.recovery_generation.fetch_add(1, Ordering::Relaxed);
        (0..count)
            .map(|index| {
                RecoveryCode::new(format!("RECOVERY-{generation:02}-{index:02}"))
                    .map_err(|_| MfaSecurityError::Generation)
            })
            .collect()
    }
}

impl RecoveryCodeHasher for TestSecurity {
    fn hash<'a>(&'a self, code: &'a RecoveryCode) -> MfaSecurityFuture<'a, RecoveryCodeHash> {
        Box::pin(async move {
            RecoveryCodeHash::new(format!("hash:{}", code.as_str()))
                .map_err(|_| MfaSecurityError::RecoveryCodeHash)
        })
    }

    fn verify<'a>(
        &'a self,
        code: &'a RecoveryCode,
        hash: &'a RecoveryCodeHash,
    ) -> MfaSecurityFuture<'a, bool> {
        Box::pin(async move { Ok(hash.as_str() == format!("hash:{}", code.as_str())) })
    }
}
