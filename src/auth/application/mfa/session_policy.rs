use std::{future::Future, pin::Pin, sync::Arc};

use crate::auth::{
    application::{
        authenticate_jwt::{AuthenticationError, SessionProtectionPolicy},
        mfa::ports::MfaFactorRepository,
    },
    domain::{
        mfa::{AuthenticationMethod, MfaFactorStatus},
        models::Session,
    },
};

/// Keeps pre-MFA sessions from surviving factor activation. A session
/// authenticated with TOTP or a recovery code remains valid if MFA is later
/// disabled because it already exceeds the baseline password requirement.
pub struct MfaSessionProtectionPolicy {
    factors: Arc<dyn MfaFactorRepository>,
}

impl MfaSessionProtectionPolicy {
    pub fn new(factors: Arc<dyn MfaFactorRepository>) -> Self {
        Self { factors }
    }
}

impl SessionProtectionPolicy for MfaSessionProtectionPolicy {
    fn permits<'a>(
        &'a self,
        session: &'a Session,
    ) -> Pin<Box<dyn Future<Output = Result<bool, AuthenticationError>> + Send + 'a>> {
        Box::pin(async move {
            let active = self
                .factors
                .find_by_user_id(session.user_id)
                .await
                .map_err(|error| {
                    tracing::error!(
                        error = %error,
                        error_debug = ?error,
                        user_id = session.user_id.get(),
                        "failed to evaluate session MFA protection"
                    );
                    AuthenticationError::Unavailable
                })?
                .is_some_and(|stored| stored.factor.status() == MfaFactorStatus::Active);

            Ok(!active || session.authentication_method != AuthenticationMethod::Password)
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use crate::auth::{
        application::mfa::ports::{AtomicMfaUpdate, MfaRepositoryFuture, StoredTotpFactor},
        domain::{
            mfa::{EncryptedTotpSecret, MfaEnrollmentId, RecoveryCodeHash, TotpFactor},
            models::{SessionId, UserId},
        },
    };

    use super::*;

    struct Factors(Option<StoredTotpFactor>);

    impl MfaFactorRepository for Factors {
        fn find_by_user_id<'a>(
            &'a self,
            _user_id: UserId,
        ) -> MfaRepositoryFuture<'a, Option<StoredTotpFactor>> {
            Box::pin(async { Ok(self.0.clone()) })
        }

        fn replace_pending<'a>(
            &'a self,
            _factor: &'a TotpFactor,
            _pending_expires_at: chrono::DateTime<Utc>,
        ) -> MfaRepositoryFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn activate_pending<'a>(
            &'a self,
            _user_id: UserId,
            _enrollment_id: MfaEnrollmentId,
            _now: chrono::DateTime<Utc>,
            _accepted_step: u64,
            _recovery_code_hashes: &'a [RecoveryCodeHash],
        ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
            Box::pin(async { Ok(AtomicMfaUpdate::Applied) })
        }

        fn disable_active<'a>(
            &'a self,
            _user_id: UserId,
            _disabled_at: chrono::DateTime<Utc>,
        ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
            Box::pin(async { Ok(AtomicMfaUpdate::Applied) })
        }

        fn accept_totp_step<'a>(
            &'a self,
            _user_id: UserId,
            _step: u64,
        ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
            Box::pin(async { Ok(AtomicMfaUpdate::Applied) })
        }

        fn consume_recovery_code<'a>(
            &'a self,
            _user_id: UserId,
            _hash: &'a RecoveryCodeHash,
        ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
            Box::pin(async { Ok(AtomicMfaUpdate::Applied) })
        }

        fn replace_recovery_codes<'a>(
            &'a self,
            _user_id: UserId,
            _hashes: &'a [RecoveryCodeHash],
        ) -> MfaRepositoryFuture<'a, AtomicMfaUpdate> {
            Box::pin(async { Ok(AtomicMfaUpdate::Applied) })
        }
    }

    fn session(authentication_method: AuthenticationMethod) -> Session {
        Session {
            id: SessionId::new("session-1").unwrap(),
            user_id: UserId::new(42).unwrap(),
            expires_at: Utc::now() + Duration::minutes(5),
            revoked_at: None,
            authentication_method,
        }
    }

    fn active_factor() -> StoredTotpFactor {
        let now = Utc::now();
        let mut factor = TotpFactor::pending(
            UserId::new(42).unwrap(),
            MfaEnrollmentId::new(),
            EncryptedTotpSecret::new(vec![1]).unwrap(),
            1,
            now,
        )
        .unwrap();
        factor.activate(now).unwrap();
        StoredTotpFactor {
            factor,
            pending_expires_at: None,
            recovery_code_hashes: Vec::new(),
        }
    }

    #[tokio::test]
    async fn active_mfa_rejects_password_only_sessions() {
        let policy = MfaSessionProtectionPolicy::new(Arc::new(Factors(Some(active_factor()))));

        assert!(
            !policy
                .permits(&session(AuthenticationMethod::Password))
                .await
                .unwrap()
        );
        assert!(
            policy
                .permits(&session(AuthenticationMethod::PasswordTotp))
                .await
                .unwrap()
        );
        assert!(
            policy
                .permits(&session(AuthenticationMethod::PasswordRecoveryCode))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn users_without_active_mfa_keep_existing_sessions() {
        let policy = MfaSessionProtectionPolicy::new(Arc::new(Factors(None)));

        assert!(
            policy
                .permits(&session(AuthenticationMethod::Password))
                .await
                .unwrap()
        );
    }
}
