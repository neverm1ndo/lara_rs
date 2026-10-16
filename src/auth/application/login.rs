use std::{future::Future, pin::Pin};

use chrono::{DateTime, Duration, Timelike, Utc};
use thiserror::Error;

use crate::auth::{
    application::{
        authenticate_credentials::{
            CredentialAuthenticationError, CredentialAuthenticationService,
        },
        jwt_issuer::JwtIssuer,
        login_user_repository::LoginUserRepository,
        password_verifier::PasswordVerifier,
        session_id_generator::SessionIdGenerator,
        session_repository::SessionRepository,
    },
    domain::models::{AuthenticatedUser, JwtClaims, Session},
};

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum LoginConfigurationError {
    #[error("JWT issuer must not be empty")]
    EmptyIssuer,
    #[error("JWT audience must not be empty")]
    EmptyAudience,
    #[error("JWT TTL must be positive")]
    InvalidTtl,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum LoginError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("authentication dependency is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginResult {
    pub access_token: String,
    pub expires_at: DateTime<Utc>,
    pub user: AuthenticatedUser,
}

pub trait Login: Send + Sync {
    fn login<'a>(
        &'a self,
        email: &'a str,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<LoginResult, LoginError>> + Send + 'a>>;
}

pub struct LoginService<P, U, S, G, J> {
    credentials: CredentialAuthenticationService<P, U>,
    sessions: S,
    session_ids: G,
    jwt_issuer: J,
    issuer: String,
    audience: String,
    ttl: Duration,
}

impl<P, U, S, G, J> LoginService<P, U, S, G, J> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        password_verifier: P,
        users: U,
        sessions: S,
        session_ids: G,
        jwt_issuer: J,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        ttl_seconds: i64,
    ) -> Result<Self, LoginConfigurationError> {
        let issuer = issuer.into();
        if issuer.trim().is_empty() {
            return Err(LoginConfigurationError::EmptyIssuer);
        }

        let audience = audience.into();
        if audience.trim().is_empty() {
            return Err(LoginConfigurationError::EmptyAudience);
        }

        let ttl = Duration::try_seconds(ttl_seconds)
            .filter(|ttl| *ttl > Duration::zero())
            .ok_or(LoginConfigurationError::InvalidTtl)?;

        Ok(Self {
            credentials: CredentialAuthenticationService::new(password_verifier, users),
            sessions,
            session_ids,
            jwt_issuer,
            issuer,
            audience,
            ttl,
        })
    }
}

impl<P, U, S, G, J> LoginService<P, U, S, G, J>
where
    P: PasswordVerifier,
    U: LoginUserRepository,
    S: SessionRepository,
    G: SessionIdGenerator,
    J: JwtIssuer,
{
    pub async fn execute(&self, email: &str, password: &str) -> Result<LoginResult, LoginError> {
        let verified = self
            .credentials
            .authenticate(email, password)
            .await
            .map_err(LoginError::from)?;

        // JWT timestamps have second precision. Truncating once keeps JWT
        // `exp` and the MongoDB session expiration exactly aligned.
        let issued_at = Utc::now()
            .with_nanosecond(0)
            .ok_or(LoginError::Unavailable)?;
        let expires_at = issued_at
            .checked_add_signed(self.ttl)
            .ok_or(LoginError::Unavailable)?;
        let session_id = self.session_ids.generate();

        let claims = JwtClaims {
            sub: verified.user_id,
            sid: session_id.clone(),
            exp: expires_at.timestamp(),
            iat: issued_at.timestamp(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
        };
        let access_token = self.jwt_issuer.issue(&claims).map_err(|error| {
            tracing::error!(
                error = %error,
                error_debug = ?error,
                "failed to issue JWT during login"
            );
            LoginError::Unavailable
        })?;

        let session = Session {
            id: session_id,
            user_id: verified.user_id,
            expires_at,
            revoked_at: None,
        };
        self.sessions.create(&session).await.map_err(|error| {
            tracing::error!(
                error = %error,
                error_debug = ?error,
                user_id = session.user_id.get(),
                "failed to persist authentication session"
            );
            LoginError::Unavailable
        })?;

        Ok(LoginResult {
            access_token,
            expires_at,
            user: verified.user,
        })
    }
}

impl From<CredentialAuthenticationError> for LoginError {
    fn from(error: CredentialAuthenticationError) -> Self {
        match error {
            CredentialAuthenticationError::InvalidCredentials => Self::InvalidCredentials,
            CredentialAuthenticationError::Unavailable => Self::Unavailable,
        }
    }
}

impl<P, U, S, G, J> Login for LoginService<P, U, S, G, J>
where
    P: PasswordVerifier,
    U: LoginUserRepository,
    S: SessionRepository,
    G: SessionIdGenerator,
    J: JwtIssuer,
{
    fn login<'a>(
        &'a self,
        email: &'a str,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<LoginResult, LoginError>> + Send + 'a>> {
        Box::pin(self.execute(email, password))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        future, io,
        sync::{Arc, Mutex},
    };

    use crate::{
        auth::{
            application::login_user_repository::LoginUser,
            domain::models::{SessionId, UserId},
        },
        shared::user_role::UserRole,
    };

    use super::*;

    struct Passwords(bool);

    impl PasswordVerifier for Passwords {
        fn verify(&self, _password: &str, _stored_hash: &str) -> bool {
            self.0
        }
    }

    #[derive(Clone)]
    struct Users(Option<LoginUser>);

    impl LoginUserRepository for Users {
        type Error = Infallible;

        fn find_by_email(
            &self,
            _email: &str,
        ) -> impl Future<Output = Result<Option<LoginUser>, Self::Error>> + Send {
            future::ready(Ok(self.0.clone()))
        }
    }

    #[derive(Clone, Default)]
    struct Sessions {
        created: Arc<Mutex<Vec<Session>>>,
        fail_create: bool,
    }

    impl SessionRepository for Sessions {
        type Error = io::Error;

        fn create(
            &self,
            session: &Session,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            if self.fail_create {
                return future::ready(Err(io::Error::other("MongoDB unavailable")));
            }

            self.created.lock().unwrap().push(session.clone());
            future::ready(Ok(()))
        }

        fn find_by_id(
            &self,
            _session_id: &SessionId,
        ) -> impl Future<Output = Result<Option<Session>, Self::Error>> + Send {
            future::ready(Ok(None))
        }
    }

    struct SessionIds;

    impl SessionIdGenerator for SessionIds {
        fn generate(&self) -> SessionId {
            SessionId::new("session-1").unwrap()
        }
    }

    #[derive(Clone, Default)]
    struct Issuer {
        claims: Arc<Mutex<Vec<JwtClaims>>>,
        fail: bool,
    }

    impl JwtIssuer for Issuer {
        type Error = io::Error;

        fn issue(&self, claims: &JwtClaims) -> Result<String, Self::Error> {
            self.claims.lock().unwrap().push(claims.clone());
            if self.fail {
                Err(io::Error::other("signing failed"))
            } else {
                Ok("signed.jwt".into())
            }
        }
    }

    fn user() -> LoginUser {
        LoginUser {
            id: UserId::new(42).unwrap(),
            username: "neo".into(),
            main_group: UserRole::Admin,
            permissions: vec![UserRole::Admin],
            avatar: None,
            password_hash: "stored-hash".into(),
        }
    }

    fn service(
        password_is_valid: bool,
        user: Option<LoginUser>,
        sessions: Sessions,
        issuer: Issuer,
    ) -> LoginService<Passwords, Users, Sessions, SessionIds, Issuer> {
        LoginService::new(
            Passwords(password_is_valid),
            Users(user),
            sessions,
            SessionIds,
            issuer,
            "lara",
            "lara-api",
            3_600,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn signs_matching_claims_then_persists_session() {
        let sessions = Sessions::default();
        let issuer = Issuer::default();
        let service = service(true, Some(user()), sessions.clone(), issuer.clone());

        let result = service.execute("neo@example.com", "correct").await.unwrap();

        assert_eq!(result.access_token, "signed.jwt");
        assert_eq!(result.user.username, "neo");

        let claims = issuer.claims.lock().unwrap()[0].clone();
        let session = sessions.created.lock().unwrap()[0].clone();
        assert_eq!(claims.sub, session.user_id);
        assert_eq!(claims.sid, session.id);
        assert_eq!(claims.exp, session.expires_at.timestamp());
        assert_eq!(result.expires_at, session.expires_at);
        assert_eq!(claims.exp - claims.iat, 3_600);
        assert_eq!(claims.iss, "lara");
        assert_eq!(claims.aud, "lara-api");
        assert_eq!(session.revoked_at, None);
    }

    #[tokio::test]
    async fn rejects_invalid_credentials_without_issuing_token_or_session() {
        let sessions = Sessions::default();
        let issuer = Issuer::default();
        let service = service(false, Some(user()), sessions.clone(), issuer.clone());

        assert_eq!(
            service.execute("neo@example.com", "wrong").await,
            Err(LoginError::InvalidCredentials)
        );
        assert!(issuer.claims.lock().unwrap().is_empty());
        assert!(sessions.created.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn does_not_create_session_when_signing_fails() {
        let sessions = Sessions::default();
        let issuer = Issuer {
            fail: true,
            ..Issuer::default()
        };
        let service = service(true, Some(user()), sessions.clone(), issuer);

        assert_eq!(
            service.execute("neo@example.com", "correct").await,
            Err(LoginError::Unavailable)
        );
        assert!(sessions.created.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn does_not_return_signed_token_when_session_write_fails() {
        let sessions = Sessions {
            fail_create: true,
            ..Sessions::default()
        };
        let issuer = Issuer::default();
        let service = service(true, Some(user()), sessions, issuer.clone());

        assert_eq!(
            service.execute("neo@example.com", "correct").await,
            Err(LoginError::Unavailable)
        );
        assert_eq!(issuer.claims.lock().unwrap().len(), 1);
    }

    #[test]
    fn validates_login_configuration() {
        let build = |issuer, audience, ttl| {
            LoginService::new(
                Passwords(true),
                Users(Some(user())),
                Sessions::default(),
                SessionIds,
                Issuer::default(),
                issuer,
                audience,
                ttl,
            )
        };

        assert!(matches!(
            build("", "lara-api", 3_600),
            Err(LoginConfigurationError::EmptyIssuer)
        ));
        assert!(matches!(
            build("lara", "", 3_600),
            Err(LoginConfigurationError::EmptyAudience)
        ));
        assert!(matches!(
            build("lara", "lara-api", 0),
            Err(LoginConfigurationError::InvalidTtl)
        ));
    }
}
