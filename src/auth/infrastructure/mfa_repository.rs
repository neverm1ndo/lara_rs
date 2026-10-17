use std::time::Duration;

use chrono::{DateTime, Utc};
use mongodb::{
    Collection, Database, IndexModel,
    bson::{Binary, DateTime as BsonDateTime, doc, spec::BinarySubtype},
    error::{Error as MongoError, ErrorKind, WriteFailure},
    options::IndexOptions,
};
use serde::{Deserialize, Serialize};

use crate::auth::{
    application::mfa::ports::{
        AtomicMfaUpdate, MfaChallengeRepository, MfaFactorRepository, MfaRepositoryError,
        MfaRepositoryFuture, StoredTotpFactor,
    },
    domain::{
        mfa::{
            EncryptedTotpSecret, MfaChallengeTokenHash, MfaEnrollmentId, MfaFactorStatus,
            MfaLoginChallenge, MfaLoginChallengeId, RecoveryCodeHash, TotpFactor,
            VerificationAttempts,
        },
        models::UserId,
    },
};

const MFA_FACTOR_COLLECTION: &str = "auth_mfa_factors";
const MFA_CHALLENGE_COLLECTION: &str = "auth_mfa_login_challenges";
const DUPLICATE_KEY_CODE: i32 = 11_000;

#[derive(Debug, Clone)]
pub struct MongoMfaFactorRepository {
    factors: Collection<TotpFactorDocument>,
}

impl MongoMfaFactorRepository {
    pub fn new(database: Database) -> Self {
        Self {
            factors: database.collection(MFA_FACTOR_COLLECTION),
        }
    }

    /// `_id` is the phpBB user ID and therefore already provides the unique
    /// one-factor-per-user constraint. The partial TTL index only removes
    /// abandoned pending enrollments; activation unsets the indexed field.
    pub async fn ensure_indexes(&self) -> Result<(), MfaRepositoryError> {
        let pending_ttl = IndexModel::builder()
            .keys(doc! { "pending_expires_at": 1 })
            .options(
                IndexOptions::builder()
                    .name(Some("auth_mfa_pending_enrollment_ttl".into()))
                    .expire_after(Some(Duration::ZERO))
                    .partial_filter_expression(Some(doc! { "status": "pending" }))
                    .build(),
            )
            .build();

        self.factors
            .create_index(pending_ttl)
            .await
            .map_err(database_error)?;
        Ok(())
    }
}

impl MfaFactorRepository for MongoMfaFactorRepository {
    fn find_by_user_id<'a>(
        &'a self,
        user_id: UserId,
    ) -> MfaRepositoryFuture<'a, Option<StoredTotpFactor>> {
        Box::pin(async move {
            self.factors
                .find_one(doc! { "_id": user_id.get() })
                .await
                .map_err(database_error)?
                .map(StoredTotpFactor::try_from)
                .transpose()
        })
    }

    fn replace_pending<'a>(
        &'a self,
        factor: &'a TotpFactor,
        pending_expires_at: DateTime<Utc>,
    ) -> MfaRepositoryFuture<'a, ()> {
        Box::pin(async move {
            let document = TotpFactorDocument::pending(factor, pending_expires_at)?;
            let filter = doc! {
                "_id": factor.user_id().get(),
                "status": { "$ne": "active" }
            };
            match self
                .factors
                .replace_one(filter, document)
                .upsert(true)
                .await
            {
                Ok(_) => Ok(()),
                Err(error) if is_duplicate_key(&error) => Err(MfaRepositoryError::Conflict),
                Err(error) => Err(database_error(error)),
            }
        })
    }

    fn activate_pending<'a>(
        &'a self,
        user_id: UserId,
        enrollment_id: MfaEnrollmentId,
        now: DateTime<Utc>,
        recovery_code_hashes: &'a [RecoveryCodeHash],
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
        Box::pin(async move {
            if recovery_code_hashes.is_empty() {
                return Err(invalid_data("recovery code hashes must not be empty"));
            }
            let hashes = recovery_code_hashes
                .iter()
                .map(|hash| hash.as_str().to_owned())
                .collect::<Vec<_>>();
            let result = self
                .factors
                .update_one(
                    doc! {
                        "_id": user_id.get(),
                        "status": "pending",
                        "enrollment_id": enrollment_id.to_string(),
                        "pending_expires_at": { "$gt": to_bson_datetime(now) }
                    },
                    doc! {
                        "$set": {
                            "status": "active",
                            "enabled_at": to_bson_datetime(now),
                            "recovery_code_hashes": hashes
                        },
                        "$unset": { "pending_expires_at": "" }
                    },
                )
                .await
                .map_err(database_error)?;
            Ok(update_outcome(result.modified_count))
        })
    }

    fn disable_active<'a>(
        &'a self,
        user_id: UserId,
        disabled_at: DateTime<Utc>,
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
        Box::pin(async move {
            let result = self
                .factors
                .update_one(
                    doc! { "_id": user_id.get(), "status": "active" },
                    doc! {
                        "$set": {
                            "status": "disabled",
                            "disabled_at": to_bson_datetime(disabled_at)
                        }
                    },
                )
                .await
                .map_err(database_error)?;
            Ok(update_outcome(result.modified_count))
        })
    }

    fn accept_totp_step<'a>(
        &'a self,
        user_id: UserId,
        step: u64,
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
        Box::pin(async move {
            let step = u64_to_i64(step, "last_accepted_step")?;
            let result = self
                .factors
                .update_one(
                    doc! {
                        "_id": user_id.get(),
                        "status": "active",
                        "$or": [
                            { "last_accepted_step": { "$exists": false } },
                            { "last_accepted_step": { "$lt": step } }
                        ]
                    },
                    doc! { "$set": { "last_accepted_step": step } },
                )
                .await
                .map_err(database_error)?;
            Ok(update_outcome(result.modified_count))
        })
    }

    fn consume_recovery_code<'a>(
        &'a self,
        user_id: UserId,
        hash: &'a RecoveryCodeHash,
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
        Box::pin(async move {
            let result = self
                .factors
                .update_one(
                    doc! {
                        "_id": user_id.get(),
                        "status": "active",
                        "recovery_code_hashes": hash.as_str()
                    },
                    doc! { "$pull": { "recovery_code_hashes": hash.as_str() } },
                )
                .await
                .map_err(database_error)?;
            Ok(update_outcome(result.modified_count))
        })
    }

    fn replace_recovery_codes<'a>(
        &'a self,
        user_id: UserId,
        hashes: &'a [RecoveryCodeHash],
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
        Box::pin(async move {
            if hashes.is_empty() {
                return Err(invalid_data("recovery code hashes must not be empty"));
            }
            let hashes = hashes
                .iter()
                .map(|hash| hash.as_str().to_owned())
                .collect::<Vec<_>>();
            let result = self
                .factors
                .update_one(
                    doc! { "_id": user_id.get(), "status": "active" },
                    doc! { "$set": { "recovery_code_hashes": hashes } },
                )
                .await
                .map_err(database_error)?;
            Ok(update_outcome(result.modified_count))
        })
    }
}

#[derive(Debug, Clone)]
pub struct MongoMfaChallengeRepository {
    challenges: Collection<MfaChallengeDocument>,
}

impl MongoMfaChallengeRepository {
    pub fn new(database: Database) -> Self {
        Self {
            challenges: database.collection(MFA_CHALLENGE_COLLECTION),
        }
    }

    pub async fn ensure_indexes(&self) -> Result<(), MfaRepositoryError> {
        let token_hash = IndexModel::builder()
            .keys(doc! { "token_hash": 1 })
            .options(
                IndexOptions::builder()
                    .name(Some("auth_mfa_challenge_token_hash_unique".into()))
                    .unique(Some(true))
                    .build(),
            )
            .build();
        let ttl = IndexModel::builder()
            .keys(doc! { "expires_at": 1 })
            .options(
                IndexOptions::builder()
                    .name(Some("auth_mfa_challenge_expires_at_ttl".into()))
                    .expire_after(Some(Duration::ZERO))
                    .build(),
            )
            .build();

        self.challenges
            .create_indexes([token_hash, ttl])
            .await
            .map_err(database_error)?;
        Ok(())
    }
}

impl MfaChallengeRepository for MongoMfaChallengeRepository {
    fn create<'a>(
        &'a self,
        challenge: &'a MfaLoginChallenge,
        token_hash: MfaChallengeTokenHash,
    ) -> MfaRepositoryFuture<'a, ()> {
        Box::pin(async move {
            let document = MfaChallengeDocument::from_domain(challenge, token_hash)?;
            match self.challenges.insert_one(document).await {
                Ok(_) => Ok(()),
                Err(error) if is_duplicate_key(&error) => Err(MfaRepositoryError::Conflict),
                Err(error) => Err(database_error(error)),
            }
        })
    }

    fn find_available_by_token_hash<'a>(
        &'a self,
        token_hash: MfaChallengeTokenHash,
        now: DateTime<Utc>,
    ) -> MfaRepositoryFuture<'a, Option<MfaLoginChallenge>> {
        Box::pin(async move {
            self.challenges
                .find_one(doc! {
                    "token_hash": binary(token_hash.as_bytes().to_vec()),
                    "consumed_at": { "$exists": false },
                    "attempts_remaining": { "$gt": 0 },
                    "expires_at": { "$gt": to_bson_datetime(now) }
                })
                .await
                .map_err(database_error)?
                .map(MfaLoginChallenge::try_from)
                .transpose()
        })
    }

    fn record_failed_attempt<'a>(
        &'a self,
        challenge_id: MfaLoginChallengeId,
        now: DateTime<Utc>,
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
        Box::pin(async move {
            let result = self
                .challenges
                .update_one(
                    available_challenge_filter(challenge_id, now),
                    doc! { "$inc": { "attempts_remaining": -1 } },
                )
                .await
                .map_err(database_error)?;
            Ok(update_outcome(result.modified_count))
        })
    }

    fn consume<'a>(
        &'a self,
        challenge_id: MfaLoginChallengeId,
        now: DateTime<Utc>,
    ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
        Box::pin(async move {
            let result = self
                .challenges
                .update_one(
                    available_challenge_filter(challenge_id, now),
                    doc! { "$set": { "consumed_at": to_bson_datetime(now) } },
                )
                .await
                .map_err(database_error)?;
            Ok(update_outcome(result.modified_count))
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TotpFactorDocument {
    #[serde(rename = "_id")]
    user_id: i64,
    kind: String,
    status: String,
    enrollment_id: String,
    encrypted_secret: Binary,
    key_version: i64,
    created_at: BsonDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_expires_at: Option<BsonDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    enabled_at: Option<BsonDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    disabled_at: Option<BsonDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_accepted_step: Option<i64>,
    #[serde(default)]
    recovery_code_hashes: Vec<String>,
}

impl TotpFactorDocument {
    fn pending(
        factor: &TotpFactor,
        pending_expires_at: DateTime<Utc>,
    ) -> Result<Self, MfaRepositoryError> {
        if factor.status() != MfaFactorStatus::Pending || pending_expires_at <= factor.created_at()
        {
            return Err(invalid_data(
                "only a pending factor with a future expiration can be stored",
            ));
        }
        Ok(Self {
            user_id: factor.user_id().get(),
            kind: "totp".into(),
            status: "pending".into(),
            enrollment_id: factor.enrollment_id().to_string(),
            encrypted_secret: binary(factor.encrypted_secret().as_bytes().to_vec()),
            key_version: i64::from(factor.key_version()),
            created_at: to_bson_datetime(factor.created_at()),
            pending_expires_at: Some(to_bson_datetime(pending_expires_at)),
            enabled_at: None,
            disabled_at: None,
            last_accepted_step: None,
            recovery_code_hashes: Vec::new(),
        })
    }
}

impl TryFrom<TotpFactorDocument> for StoredTotpFactor {
    type Error = MfaRepositoryError;

    fn try_from(document: TotpFactorDocument) -> Result<Self, Self::Error> {
        if document.kind != "totp" {
            return Err(invalid_data("unknown MFA factor kind"));
        }
        let user_id = UserId::new(document.user_id).map_err(invalid_domain)?;
        let enrollment_id = document
            .enrollment_id
            .parse::<MfaEnrollmentId>()
            .map_err(invalid_domain)?;
        let encrypted_secret =
            EncryptedTotpSecret::new(document.encrypted_secret.bytes).map_err(invalid_domain)?;
        let key_version = u32::try_from(document.key_version)
            .map_err(|_| invalid_data("encryption key version is outside u32"))?;
        let created_at = from_bson_datetime(document.created_at)?;
        let enabled_at = document.enabled_at.map(from_bson_datetime).transpose()?;
        let pending_expires_at = document
            .pending_expires_at
            .map(from_bson_datetime)
            .transpose()?;
        let disabled_at = document.disabled_at.map(from_bson_datetime).transpose()?;
        let last_accepted_step = document
            .last_accepted_step
            .map(|step| i64_to_u64(step, "last_accepted_step"))
            .transpose()?;
        let recovery_code_hashes = document
            .recovery_code_hashes
            .into_iter()
            .map(|hash| RecoveryCodeHash::new(hash).map_err(invalid_domain))
            .collect::<Result<Vec<_>, _>>()?;

        let mut factor = TotpFactor::pending(
            user_id,
            enrollment_id,
            encrypted_secret,
            key_version,
            created_at,
        )
        .map_err(invalid_domain)?;

        match document.status.as_str() {
            "pending" => {
                if pending_expires_at.is_none()
                    || enabled_at.is_some()
                    || disabled_at.is_some()
                    || last_accepted_step.is_some()
                    || !recovery_code_hashes.is_empty()
                {
                    return Err(invalid_data("inconsistent pending TOTP factor"));
                }
            }
            "active" | "disabled" => {
                if pending_expires_at.is_some()
                    || disabled_at.is_some() != (document.status == "disabled")
                    || recovery_code_hashes.is_empty()
                {
                    return Err(invalid_data("inconsistent active TOTP factor"));
                }
                factor
                    .activate(
                        enabled_at
                            .ok_or_else(|| invalid_data("active factor has no enabled_at"))?,
                    )
                    .map_err(invalid_domain)?;
                if let Some(step) = last_accepted_step {
                    factor.accept_step(step).map_err(invalid_domain)?;
                }
                if document.status == "disabled" {
                    factor.disable().map_err(invalid_domain)?;
                }
            }
            _ => return Err(invalid_data("unknown MFA factor status")),
        }

        Ok(Self {
            factor,
            pending_expires_at,
            recovery_code_hashes,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct MfaChallengeDocument {
    #[serde(rename = "_id")]
    id: String,
    user_id: i64,
    token_hash: Binary,
    created_at: BsonDateTime,
    expires_at: BsonDateTime,
    attempts_remaining: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumed_at: Option<BsonDateTime>,
}

impl MfaChallengeDocument {
    fn from_domain(
        challenge: &MfaLoginChallenge,
        token_hash: MfaChallengeTokenHash,
    ) -> Result<Self, MfaRepositoryError> {
        if challenge.consumed_at().is_some() || challenge.attempts().is_exhausted() {
            return Err(invalid_data("only an available challenge can be inserted"));
        }
        Ok(Self {
            id: challenge.id().to_string(),
            user_id: challenge.user_id().get(),
            token_hash: binary(token_hash.as_bytes().to_vec()),
            created_at: to_bson_datetime(challenge.created_at()),
            expires_at: to_bson_datetime(challenge.expires_at()),
            attempts_remaining: i64::from(challenge.attempts().remaining()),
            consumed_at: None,
        })
    }
}

impl TryFrom<MfaChallengeDocument> for MfaLoginChallenge {
    type Error = MfaRepositoryError;

    fn try_from(document: MfaChallengeDocument) -> Result<Self, Self::Error> {
        if document.consumed_at.is_some() {
            return Err(invalid_data(
                "consumed challenge cannot be returned as available",
            ));
        }
        let id = document
            .id
            .parse::<MfaLoginChallengeId>()
            .map_err(invalid_domain)?;
        let user_id = UserId::new(document.user_id).map_err(invalid_domain)?;
        let attempts = u16::try_from(document.attempts_remaining)
            .map_err(|_| invalid_data("challenge attempts are outside u16"))?;
        MfaLoginChallenge::new(
            id,
            user_id,
            from_bson_datetime(document.created_at)?,
            from_bson_datetime(document.expires_at)?,
            VerificationAttempts::new(attempts).map_err(invalid_domain)?,
        )
        .map_err(invalid_domain)
    }
}

fn available_challenge_filter(
    challenge_id: MfaLoginChallengeId,
    now: DateTime<Utc>,
) -> mongodb::bson::Document {
    doc! {
        "_id": challenge_id.to_string(),
        "consumed_at": { "$exists": false },
        "attempts_remaining": { "$gt": 0 },
        "expires_at": { "$gt": to_bson_datetime(now) }
    }
}

fn binary(bytes: Vec<u8>) -> Binary {
    Binary {
        subtype: BinarySubtype::Generic,
        bytes,
    }
}

fn update_outcome(modified_count: u64) -> AtomicMfaUpdate {
    if modified_count == 1 {
        AtomicMfaUpdate::Applied
    } else {
        AtomicMfaUpdate::Rejected
    }
}

fn to_bson_datetime(value: DateTime<Utc>) -> BsonDateTime {
    BsonDateTime::from_millis(value.timestamp_millis())
}

fn from_bson_datetime(value: BsonDateTime) -> Result<DateTime<Utc>, MfaRepositoryError> {
    DateTime::from_timestamp_millis(value.timestamp_millis())
        .ok_or_else(|| invalid_data("timestamp is outside the chrono range"))
}

fn u64_to_i64(value: u64, field: &str) -> Result<i64, MfaRepositoryError> {
    i64::try_from(value).map_err(|_| invalid_data(format!("{field} exceeds BSON i64")))
}

fn i64_to_u64(value: i64, field: &str) -> Result<u64, MfaRepositoryError> {
    u64::try_from(value).map_err(|_| invalid_data(format!("{field} cannot be negative")))
}

fn invalid_domain(error: impl std::fmt::Display) -> MfaRepositoryError {
    invalid_data(error.to_string())
}

fn invalid_data(message: impl Into<String>) -> MfaRepositoryError {
    MfaRepositoryError::InvalidData {
        message: message.into(),
    }
}

fn database_error(error: MongoError) -> MfaRepositoryError {
    MfaRepositoryError::Unavailable {
        message: error.to_string(),
    }
}

fn is_duplicate_key(error: &MongoError) -> bool {
    matches!(
        error.kind.as_ref(),
        ErrorKind::Write(WriteFailure::WriteError(error)) if error.code == DUPLICATE_KEY_CODE
    )
}

#[cfg(test)]
mod tests {
    use chrono::Duration as ChronoDuration;

    use super::*;

    fn timestamp(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).unwrap()
    }

    fn pending_factor() -> TotpFactor {
        TotpFactor::pending(
            UserId::new(42).unwrap(),
            MfaEnrollmentId::new(),
            EncryptedTotpSecret::new(vec![1, 2, 3]).unwrap(),
            1,
            timestamp(1_000),
        )
        .unwrap()
    }

    #[test]
    fn maps_pending_factor_without_exposing_plaintext_secret() {
        let factor = pending_factor();
        let expires_at = timestamp(1_600);
        let document = TotpFactorDocument::pending(&factor, expires_at).unwrap();

        assert_eq!(document.user_id, 42);
        assert_eq!(document.status, "pending");
        assert_eq!(document.encrypted_secret.bytes, vec![1, 2, 3]);
        assert_eq!(
            document.pending_expires_at.unwrap().timestamp_millis(),
            1_600_000
        );

        let stored = StoredTotpFactor::try_from(document).unwrap();
        assert_eq!(stored.factor, factor);
        assert_eq!(stored.pending_expires_at, Some(expires_at));
        assert!(stored.recovery_code_hashes.is_empty());
    }

    #[test]
    fn rehydrates_active_and_disabled_factors_with_replay_state() {
        for (status, disabled_at) in [
            ("active", None),
            ("disabled", Some(BsonDateTime::from_millis(1_300_000))),
        ] {
            let pending = pending_factor();
            let document = TotpFactorDocument {
                user_id: pending.user_id().get(),
                kind: "totp".into(),
                status: status.into(),
                enrollment_id: pending.enrollment_id().to_string(),
                encrypted_secret: binary(vec![1, 2, 3]),
                key_version: 1,
                created_at: BsonDateTime::from_millis(1_000_000),
                pending_expires_at: None,
                enabled_at: Some(BsonDateTime::from_millis(1_100_000)),
                disabled_at,
                last_accepted_step: Some(41),
                recovery_code_hashes: vec!["$hash$one".into()],
            };

            let stored = StoredTotpFactor::try_from(document).unwrap();
            assert_eq!(stored.factor.last_accepted_step(), Some(41));
            assert_eq!(
                stored.factor.status(),
                if status == "active" {
                    MfaFactorStatus::Active
                } else {
                    MfaFactorStatus::Disabled
                }
            );
        }
    }

    #[test]
    fn rejects_inconsistent_factor_documents() {
        let pending = pending_factor();
        let mut document = TotpFactorDocument::pending(
            &pending,
            pending.created_at() + ChronoDuration::minutes(10),
        )
        .unwrap();
        document.last_accepted_step = Some(1);

        assert!(StoredTotpFactor::try_from(document).is_err());
    }

    #[test]
    fn maps_available_challenge_and_rejects_consumed_or_exhausted_documents() {
        let challenge = MfaLoginChallenge::new(
            MfaLoginChallengeId::new(),
            UserId::new(42).unwrap(),
            timestamp(1_000),
            timestamp(1_300),
            VerificationAttempts::new(5).unwrap(),
        )
        .unwrap();
        let hash = MfaChallengeTokenHash::new([7; 32]);
        let document = MfaChallengeDocument::from_domain(&challenge, hash).unwrap();

        assert_eq!(document.token_hash.bytes, vec![7; 32]);
        assert_eq!(
            MfaLoginChallenge::try_from(document.clone()).unwrap(),
            challenge
        );

        let mut consumed = document.clone();
        consumed.consumed_at = Some(BsonDateTime::from_millis(1_100_000));
        assert!(MfaLoginChallenge::try_from(consumed).is_err());

        let mut exhausted = document;
        exhausted.attempts_remaining = 0;
        assert!(MfaLoginChallenge::try_from(exhausted).is_err());
    }

    #[test]
    fn atomic_update_outcome_requires_exactly_one_modified_document() {
        assert_eq!(update_outcome(0), AtomicMfaUpdate::Rejected);
        assert_eq!(update_outcome(1), AtomicMfaUpdate::Applied);
        assert_eq!(update_outcome(2), AtomicMfaUpdate::Rejected);
    }
}
