use std::{future::Future, pin::Pin, sync::Arc};

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;

use crate::auth::{
    application::{
        authenticate_credentials::{
            CredentialAuthenticationError, CredentialAuthenticationService,
        },
        authenticate_jwt::AuthenticatedUserRepository,
        jwt_issuer::JwtIssuer,
        login::{AuthenticatedSessionIssuer, LoginError, LoginResult},
        login_user_repository::LoginUserRepository,
        mfa::{
            ports::{
                MfaChallengeRepository, MfaChallengeTokenGenerator, MfaChallengeTokenHasher,
                MfaClock, MfaFactorRepository, MfaRepositoryError,
            },
            verification::{MfaFactorVerificationService, MfaProof, MfaVerificationError},
        },
        password_verifier::PasswordVerifier,
        session_id_generator::SessionIdGenerator,
        session_repository::SessionRepository,
    },
    domain::{
        mfa::{
            MfaChallengeToken, MfaFactorStatus, MfaLoginChallenge, MfaLoginChallengeId,
            RecoveryCode, TotpCode, VerificationAttempts,
        },
        rules::is_user_in_work_group,
    },
};

#[derive(Debug, PartialEq, Eq)]
pub struct MfaChallengeResult {
    pub challenge_token: MfaChallengeToken,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MfaLoginResult {
    Authenticated(LoginResult),
    MfaRequired(MfaChallengeResult),
}

pub enum MfaLoginProof {
    Totp(TotpCode),
    RecoveryCode(RecoveryCode),
}

impl MfaLoginProof {
    fn as_factor_proof(&self) -> MfaProof<'_> {
        match self {
            Self::Totp(code) => MfaProof::Totp(code),
            Self::RecoveryCode(code) => MfaProof::RecoveryCode(code),
        }
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum MfaLoginError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("invalid or expired MFA challenge")]
    InvalidChallenge,
    #[error("invalid or replayed MFA code")]
    InvalidCode,
    #[error("authentication dependency is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum MfaLoginConfigurationError {
    #[error("MFA challenge TTL must be positive")]
    InvalidChallengeTtl,
    #[error("MFA verification attempt limit must be positive")]
    InvalidVerificationAttempts,
}

pub trait MfaLogin: Send + Sync {
    fn begin<'a>(
        &'a self,
        email: &'a str,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<MfaLoginResult, MfaLoginError>> + Send + 'a>>;

    fn complete<'a>(
        &'a self,
        challenge_token: &'a MfaChallengeToken,
        proof: &'a MfaLoginProof,
    ) -> Pin<Box<dyn Future<Output = Result<LoginResult, MfaLoginError>> + Send + 'a>>;
}

pub struct MfaLoginService<P, U, A, S, G, J> {
    credentials: CredentialAuthenticationService<P, U>,
    current_users: A,
    session_issuer: AuthenticatedSessionIssuer<S, G, J>,
    factors: Arc<dyn MfaFactorRepository>,
    challenges: Arc<dyn MfaChallengeRepository>,
    challenge_tokens: Arc<dyn MfaChallengeTokenGenerator>,
    challenge_hasher: Arc<dyn MfaChallengeTokenHasher>,
    factor_verification: Arc<MfaFactorVerificationService>,
    clock: Arc<dyn MfaClock>,
    challenge_ttl: Duration,
    max_verification_attempts: u16,
}

impl<P, U, A, S, G, J> MfaLoginService<P, U, A, S, G, J> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        password_verifier: P,
        login_users: U,
        current_users: A,
        session_issuer: AuthenticatedSessionIssuer<S, G, J>,
        factors: Arc<dyn MfaFactorRepository>,
        challenges: Arc<dyn MfaChallengeRepository>,
        challenge_tokens: Arc<dyn MfaChallengeTokenGenerator>,
        challenge_hasher: Arc<dyn MfaChallengeTokenHasher>,
        factor_verification: Arc<MfaFactorVerificationService>,
        clock: Arc<dyn MfaClock>,
        challenge_ttl_seconds: u64,
        max_verification_attempts: u16,
    ) -> Result<Self, MfaLoginConfigurationError> {
        let ttl_seconds = i64::try_from(challenge_ttl_seconds)
            .ok()
            .filter(|seconds| *seconds > 0)
            .ok_or(MfaLoginConfigurationError::InvalidChallengeTtl)?;
        VerificationAttempts::new(max_verification_attempts)
            .map_err(|_| MfaLoginConfigurationError::InvalidVerificationAttempts)?;

        Ok(Self {
            credentials: CredentialAuthenticationService::new(password_verifier, login_users),
            current_users,
            session_issuer,
            factors,
            challenges,
            challenge_tokens,
            challenge_hasher,
            factor_verification,
            clock,
            challenge_ttl: Duration::seconds(ttl_seconds),
            max_verification_attempts,
        })
    }
}

impl<P, U, A, S, G, J> MfaLoginService<P, U, A, S, G, J>
where
    P: PasswordVerifier,
    U: LoginUserRepository,
    A: AuthenticatedUserRepository,
    S: SessionRepository,
    G: SessionIdGenerator,
    J: JwtIssuer,
{
    pub async fn begin_login(
        &self,
        email: &str,
        password: &str,
    ) -> Result<MfaLoginResult, MfaLoginError> {
        let verified = self
            .credentials
            .authenticate(email, password)
            .await
            .map_err(map_credentials_error)?;
        let factor = self
            .factors
            .find_by_user_id(verified.user_id)
            .await
            .map_err(map_repository_error)?;

        if !factor.is_some_and(|stored| stored.factor.status() == MfaFactorStatus::Active) {
            let session = self
                .session_issuer
                .issue(
                    verified.user_id,
                    verified.user,
                    crate::auth::domain::mfa::AuthenticationMethod::Password,
                )
                .await
                .map_err(map_login_error)?;
            return Ok(MfaLoginResult::Authenticated(session));
        }

        let now = self.clock.now();
        let expires_at = now
            .checked_add_signed(self.challenge_ttl)
            .ok_or(MfaLoginError::Unavailable)?;
        let challenge_token = self
            .challenge_tokens
            .generate()
            .map_err(|error| map_security_failure(error, "generate MFA challenge token"))?;
        let challenge = MfaLoginChallenge::new(
            MfaLoginChallengeId::new(),
            verified.user_id,
            now,
            expires_at,
            VerificationAttempts::new(self.max_verification_attempts)
                .map_err(|_| MfaLoginError::Unavailable)?,
        )
        .map_err(|_| MfaLoginError::Unavailable)?;
        self.challenges
            .create(&challenge, self.challenge_hasher.hash(&challenge_token))
            .await
            .map_err(map_repository_error)?;

        Ok(MfaLoginResult::MfaRequired(MfaChallengeResult {
            challenge_token,
            expires_at,
        }))
    }

    pub async fn complete_login(
        &self,
        challenge_token: &MfaChallengeToken,
        proof: &MfaLoginProof,
    ) -> Result<LoginResult, MfaLoginError> {
        let now = self.clock.now();
        let challenge = self
            .challenges
            .find_available_by_token_hash(self.challenge_hasher.hash(challenge_token), now)
            .await
            .map_err(map_repository_error)?
            .ok_or(MfaLoginError::InvalidChallenge)?;

        let legacy_user_id = i32::try_from(challenge.user_id().get())
            .map_err(|_| MfaLoginError::InvalidChallenge)?;
        let user = self
            .current_users
            .find_by_id(legacy_user_id)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, error_debug = ?error, "failed to refresh user during MFA login");
                MfaLoginError::Unavailable
            })?
            .filter(|user| is_user_in_work_group(user.main_group, &user.permissions))
            .ok_or(MfaLoginError::InvalidChallenge)?;

        let authentication_method = match self
            .factor_verification
            .verify(challenge.user_id(), proof.as_factor_proof())
            .await
        {
            Ok(method) => method,
            Err(MfaVerificationError::InvalidCode | MfaVerificationError::NotFound) => {
                let recorded = self
                    .challenges
                    .record_failed_attempt(challenge.id(), now)
                    .await
                    .map_err(map_repository_error)?;
                if !recorded.was_applied() {
                    return Err(MfaLoginError::InvalidChallenge);
                }
                return Err(MfaLoginError::InvalidCode);
            }
            Err(MfaVerificationError::Unavailable) => return Err(MfaLoginError::Unavailable),
        };

        let consumed = self
            .challenges
            .consume(challenge.id(), now)
            .await
            .map_err(map_repository_error)?;
        if !consumed.was_applied() {
            return Err(MfaLoginError::InvalidChallenge);
        }

        self.session_issuer
            .issue(challenge.user_id(), user, authentication_method)
            .await
            .map_err(map_login_error)
    }
}

impl<P, U, A, S, G, J> MfaLogin for MfaLoginService<P, U, A, S, G, J>
where
    P: PasswordVerifier,
    U: LoginUserRepository,
    A: AuthenticatedUserRepository,
    S: SessionRepository,
    G: SessionIdGenerator,
    J: JwtIssuer,
{
    fn begin<'a>(
        &'a self,
        email: &'a str,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<MfaLoginResult, MfaLoginError>> + Send + 'a>> {
        Box::pin(self.begin_login(email, password))
    }

    fn complete<'a>(
        &'a self,
        challenge_token: &'a MfaChallengeToken,
        proof: &'a MfaLoginProof,
    ) -> Pin<Box<dyn Future<Output = Result<LoginResult, MfaLoginError>> + Send + 'a>> {
        Box::pin(self.complete_login(challenge_token, proof))
    }
}

fn map_credentials_error(error: CredentialAuthenticationError) -> MfaLoginError {
    match error {
        CredentialAuthenticationError::InvalidCredentials => MfaLoginError::InvalidCredentials,
        CredentialAuthenticationError::Unavailable => MfaLoginError::Unavailable,
    }
}

fn map_login_error(error: LoginError) -> MfaLoginError {
    match error {
        LoginError::InvalidCredentials => MfaLoginError::InvalidCredentials,
        LoginError::Unavailable => MfaLoginError::Unavailable,
    }
}

fn map_repository_error(error: MfaRepositoryError) -> MfaLoginError {
    match error {
        MfaRepositoryError::Conflict => MfaLoginError::InvalidChallenge,
        MfaRepositoryError::InvalidData { .. } | MfaRepositoryError::Unavailable { .. } => {
            tracing::error!(error = %error, error_debug = ?error, "MFA login repository failed");
            MfaLoginError::Unavailable
        }
    }
}

fn map_security_failure(
    error: impl std::fmt::Display + std::fmt::Debug,
    operation: &'static str,
) -> MfaLoginError {
    tracing::error!(error = %error, error_debug = ?error, operation, "MFA login security operation failed");
    MfaLoginError::Unavailable
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        future,
        sync::{Arc, Mutex},
    };

    use chrono::{TimeZone, Utc};

    use crate::{
        auth::{
            application::{
                login_user_repository::LoginUser,
                mfa::{
                    ports::{
                        MfaChallengeRepository, MfaChallengeTokenGenerator,
                        MfaChallengeTokenHasher, MfaFactorRepository, RecoveryCodeHasher,
                        StoredTotpFactor, TotpSecretCipher, TotpVerifier,
                    },
                    test_support::{FixedClock, MemoryMfaRepository, TestSecurity},
                },
            },
            domain::{
                mfa::{
                    AuthenticationMethod, EncryptedTotpSecret, MfaEnrollmentId, RecoveryCodeHash,
                    TotpFactor,
                },
                models::{AuthenticatedUser, JwtClaims, Session, SessionId, UserId},
            },
        },
        shared::user_role::UserRole,
    };

    use super::*;

    struct Passwords;

    impl PasswordVerifier for Passwords {
        fn verify(&self, password: &str, stored_hash: &str) -> bool {
            password == "correct" && stored_hash == "stored-hash"
        }
    }

    #[derive(Clone)]
    struct Users;

    impl LoginUserRepository for Users {
        type Error = Infallible;

        fn find_by_email(
            &self,
            email: &str,
        ) -> impl Future<Output = Result<Option<LoginUser>, Self::Error>> + Send {
            future::ready(Ok((email == "neo@example.com").then(login_user)))
        }
    }

    impl AuthenticatedUserRepository for Users {
        type Error = Infallible;

        fn find_by_id(
            &self,
            user_id: i32,
        ) -> impl Future<Output = Result<Option<AuthenticatedUser>, Self::Error>> + Send {
            future::ready(Ok((user_id == 42).then(authenticated_user)))
        }
    }

    #[derive(Clone, Default)]
    struct Sessions(Arc<Mutex<Vec<Session>>>);

    impl SessionRepository for Sessions {
        type Error = Infallible;

        fn create(
            &self,
            session: &Session,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            self.0.lock().unwrap().push(session.clone());
            future::ready(Ok(()))
        }

        fn find_by_id(
            &self,
            _session_id: &SessionId,
        ) -> impl Future<Output = Result<Option<Session>, Self::Error>> + Send {
            future::ready(Ok(None))
        }

        fn revoke(
            &self,
            _session_id: &SessionId,
            _revoked_at: DateTime<Utc>,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            future::ready(Ok(()))
        }
    }

    struct SessionIds;

    impl SessionIdGenerator for SessionIds {
        fn generate(&self) -> SessionId {
            SessionId::new(uuid::Uuid::new_v4().to_string()).unwrap()
        }
    }

    struct Issuer;

    impl JwtIssuer for Issuer {
        type Error = Infallible;

        fn issue(&self, _claims: &JwtClaims) -> Result<String, Self::Error> {
            Ok("signed.jwt".into())
        }
    }

    type Service = MfaLoginService<Passwords, Users, Users, Sessions, SessionIds, Issuer>;

    fn login_user() -> LoginUser {
        LoginUser {
            id: user_id(),
            username: "neo".into(),
            main_group: UserRole::Admin,
            permissions: Vec::new(),
            avatar: None,
            password_hash: "stored-hash".into(),
        }
    }

    fn authenticated_user() -> AuthenticatedUser {
        login_user().into_authenticated_user()
    }

    fn user_id() -> UserId {
        UserId::new(42).unwrap()
    }

    fn active_factor(now: DateTime<Utc>, recovery_codes: &[&str]) -> StoredTotpFactor {
        let mut factor = TotpFactor::pending(
            user_id(),
            MfaEnrollmentId::new(),
            EncryptedTotpSecret::new(b"test-secret".to_vec()).unwrap(),
            1,
            now,
        )
        .unwrap();
        factor.activate(now).unwrap();
        StoredTotpFactor {
            factor,
            pending_expires_at: None,
            recovery_code_hashes: recovery_codes
                .iter()
                .map(|code| RecoveryCodeHash::new(format!("hash:{code}")).unwrap())
                .collect(),
        }
    }

    fn service(
        repository: &Arc<MemoryMfaRepository>,
        sessions: Sessions,
        clock: &FixedClock,
        max_attempts: u16,
    ) -> Service {
        let security = Arc::new(TestSecurity::default());
        let factor_verification = Arc::new(MfaFactorVerificationService::new(
            Arc::clone(repository) as Arc<dyn MfaFactorRepository>,
            Arc::clone(&security) as Arc<dyn TotpSecretCipher>,
            Arc::clone(&security) as Arc<dyn TotpVerifier>,
            Arc::clone(&security) as Arc<dyn RecoveryCodeHasher>,
            Arc::new(clock.clone()),
        ));
        let session_issuer = AuthenticatedSessionIssuer::new(
            sessions, SessionIds, Issuer, "lara", "lara-api", 3_600,
        )
        .unwrap();

        MfaLoginService::new(
            Passwords,
            Users,
            Users,
            session_issuer,
            Arc::clone(repository) as Arc<dyn MfaFactorRepository>,
            Arc::clone(repository) as Arc<dyn MfaChallengeRepository>,
            Arc::clone(&security) as Arc<dyn MfaChallengeTokenGenerator>,
            security as Arc<dyn MfaChallengeTokenHasher>,
            factor_verification,
            Arc::new(clock.clone()),
            300,
            max_attempts,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn password_only_user_gets_session_without_challenge() {
        let repository = Arc::new(MemoryMfaRepository::default());
        let sessions = Sessions::default();
        let clock = FixedClock::at(Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap());
        let service = service(&repository, sessions.clone(), &clock, 3);

        let result = service
            .begin_login("neo@example.com", "correct")
            .await
            .unwrap();

        assert!(matches!(result, MfaLoginResult::Authenticated(_)));
        assert_eq!(sessions.0.lock().unwrap().len(), 1);
        assert_eq!(
            sessions.0.lock().unwrap()[0].authentication_method,
            AuthenticationMethod::Password
        );
    }

    #[tokio::test]
    async fn active_factor_requires_second_step_before_session_is_issued() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();
        let repository = Arc::new(MemoryMfaRepository::default());
        repository.insert_factor(active_factor(now, &["RECOVERY-00"]));
        let sessions = Sessions::default();
        let clock = FixedClock::at(now);
        let service = service(&repository, sessions.clone(), &clock, 3);

        let result = service
            .begin_login("neo@example.com", "correct")
            .await
            .unwrap();

        assert!(matches!(result, MfaLoginResult::MfaRequired(_)));
        assert!(sessions.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn totp_completes_challenge_once_and_records_strong_session() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();
        let repository = Arc::new(MemoryMfaRepository::default());
        repository.insert_factor(active_factor(now, &[]));
        let sessions = Sessions::default();
        let clock = FixedClock::at(now);
        let service = service(&repository, sessions.clone(), &clock, 3);
        let MfaLoginResult::MfaRequired(challenge) = service
            .begin_login("neo@example.com", "correct")
            .await
            .unwrap()
        else {
            panic!("expected MFA challenge");
        };
        let proof = MfaLoginProof::Totp(TotpCode::new("123456").unwrap());

        service
            .complete_login(&challenge.challenge_token, &proof)
            .await
            .unwrap();

        assert_eq!(
            sessions.0.lock().unwrap()[0].authentication_method,
            AuthenticationMethod::PasswordTotp
        );
        assert_eq!(
            service
                .complete_login(&challenge.challenge_token, &proof)
                .await,
            Err(MfaLoginError::InvalidChallenge)
        );
    }

    #[tokio::test]
    async fn failed_codes_exhaust_challenge_attempts() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();
        let repository = Arc::new(MemoryMfaRepository::default());
        repository.insert_factor(active_factor(now, &[]));
        let clock = FixedClock::at(now);
        let service = service(&repository, Sessions::default(), &clock, 2);
        let MfaLoginResult::MfaRequired(challenge) = service
            .begin_login("neo@example.com", "correct")
            .await
            .unwrap()
        else {
            panic!("expected MFA challenge");
        };
        let proof = MfaLoginProof::Totp(TotpCode::new("000000").unwrap());

        assert_eq!(
            service
                .complete_login(&challenge.challenge_token, &proof)
                .await,
            Err(MfaLoginError::InvalidCode)
        );
        assert_eq!(
            service
                .complete_login(&challenge.challenge_token, &proof)
                .await,
            Err(MfaLoginError::InvalidCode)
        );
        assert_eq!(
            service
                .complete_login(&challenge.challenge_token, &proof)
                .await,
            Err(MfaLoginError::InvalidChallenge)
        );
    }

    #[tokio::test]
    async fn recovery_code_is_consumed_and_challenge_expiration_is_enforced() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();
        let repository = Arc::new(MemoryMfaRepository::default());
        repository.insert_factor(active_factor(now, &["RECOVERY-00"]));
        let sessions = Sessions::default();
        let clock = FixedClock::at(now);
        let service = service(&repository, sessions.clone(), &clock, 3);
        let MfaLoginResult::MfaRequired(first) = service
            .begin_login("neo@example.com", "correct")
            .await
            .unwrap()
        else {
            panic!("expected MFA challenge");
        };
        let proof = MfaLoginProof::RecoveryCode(RecoveryCode::new("RECOVERY-00").unwrap());
        service
            .complete_login(&first.challenge_token, &proof)
            .await
            .unwrap();
        assert_eq!(
            sessions.0.lock().unwrap()[0].authentication_method,
            AuthenticationMethod::PasswordRecoveryCode
        );

        let MfaLoginResult::MfaRequired(second) = service
            .begin_login("neo@example.com", "correct")
            .await
            .unwrap()
        else {
            panic!("expected MFA challenge");
        };
        assert_eq!(
            service
                .complete_login(&second.challenge_token, &proof)
                .await,
            Err(MfaLoginError::InvalidCode)
        );

        let MfaLoginResult::MfaRequired(expiring) = service
            .begin_login("neo@example.com", "correct")
            .await
            .unwrap()
        else {
            panic!("expected MFA challenge");
        };
        *clock.0.lock().unwrap() = expiring.expires_at;
        assert_eq!(
            service
                .complete_login(&expiring.challenge_token, &proof)
                .await,
            Err(MfaLoginError::InvalidChallenge)
        );
    }
}
