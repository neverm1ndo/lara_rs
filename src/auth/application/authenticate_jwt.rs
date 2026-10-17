use std::{error::Error, future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::auth::{
    application::session_repository::SessionRepository,
    domain::{
        models::{AuthenticatedPrincipal, AuthenticatedUser, JwtClaims},
        rules::is_user_in_work_group,
    },
};

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum AuthenticationError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("authentication dependency is unavailable")]
    Unavailable,
}

/// Port implemented by the JWT infrastructure adapter.
pub trait JwtVerifier: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn verify(&self, token: &str) -> Result<JwtClaims, Self::Error>;
}

/// Read-only projection used by authentication to refresh user permissions.
pub trait AuthenticatedUserRepository: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn find_by_id(
        &self,
        user_id: i32,
    ) -> impl Future<Output = Result<Option<AuthenticatedUser>, Self::Error>> + Send;
}

/// Object-safe boundary consumed by the Axum presentation layer.
pub trait AuthenticateBearerToken: Send + Sync {
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<
        Box<dyn Future<Output = Result<AuthenticatedPrincipal, AuthenticationError>> + Send + 'a>,
    >;
}

pub struct JwtAuthenticationService<V, S, U> {
    verifier: V,
    sessions: S,
    users: U,
}

impl<V, S, U> JwtAuthenticationService<V, S, U> {
    pub fn new(verifier: V, sessions: S, users: U) -> Self {
        Self {
            verifier,
            sessions,
            users,
        }
    }
}

impl<V, S, U> AuthenticateBearerToken for JwtAuthenticationService<V, S, U>
where
    V: JwtVerifier,
    S: SessionRepository,
    U: AuthenticatedUserRepository,
{
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<
        Box<dyn Future<Output = Result<AuthenticatedPrincipal, AuthenticationError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let claims = self
                .verifier
                .verify(token)
                .map_err(|_| AuthenticationError::Unauthorized)?;
            let token_expires_at =
                DateTime::from_timestamp(claims.exp, 0).ok_or(AuthenticationError::Unauthorized)?;

            let session = self
                .sessions
                .find_by_id(&claims.sid)
                .await
                .map_err(|_| AuthenticationError::Unavailable)?
                .ok_or(AuthenticationError::Unauthorized)?;

            if session.id != claims.sid
                || session.user_id != claims.sub
                || !session.is_active(Utc::now())
            {
                return Err(AuthenticationError::Unauthorized);
            }

            let user_id =
                i32::try_from(claims.sub.get()).map_err(|_| AuthenticationError::Unauthorized)?;
            let user = self
                .users
                .find_by_id(user_id)
                .await
                .map_err(|_| AuthenticationError::Unavailable)?
                .ok_or(AuthenticationError::Unauthorized)?;

            if user.id != claims.sub.get()
                || !is_user_in_work_group(user.main_group, &user.permissions)
            {
                return Err(AuthenticationError::Unauthorized);
            }

            Ok(AuthenticatedPrincipal {
                user,
                session_id: session.id,
                token_expires_at,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{future, io};

    use chrono::Duration;

    use crate::auth::domain::models::{Session, SessionId, UserId};
    use crate::shared::user_role::UserRole;

    use super::*;

    struct Verifier(Result<JwtClaims, AuthenticationError>);

    impl JwtVerifier for Verifier {
        type Error = AuthenticationError;

        fn verify(&self, _token: &str) -> Result<JwtClaims, Self::Error> {
            self.0.clone()
        }
    }

    struct Sessions(Result<Option<Session>, io::Error>);

    impl SessionRepository for Sessions {
        type Error = io::Error;

        fn create(
            &self,
            _session: &Session,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            future::ready(Ok(()))
        }

        fn find_by_id(
            &self,
            _session_id: &SessionId,
        ) -> impl Future<Output = Result<Option<Session>, Self::Error>> + Send {
            future::ready(match &self.0 {
                Ok(session) => Ok(session.clone()),
                Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
            })
        }
    }

    struct Users(Result<Option<AuthenticatedUser>, io::Error>);

    impl AuthenticatedUserRepository for Users {
        type Error = io::Error;

        fn find_by_id(
            &self,
            _user_id: i32,
        ) -> impl Future<Output = Result<Option<AuthenticatedUser>, Self::Error>> + Send {
            future::ready(match &self.0 {
                Ok(user) => Ok(user.clone()),
                Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
            })
        }
    }

    fn claims() -> JwtClaims {
        let now = Utc::now().timestamp();
        JwtClaims {
            sub: UserId::new(42).unwrap(),
            sid: SessionId::new("session-1").unwrap(),
            exp: now + 60,
            iat: now,
            iss: "lara".into(),
            aud: "lara-api".into(),
        }
    }

    fn session() -> Session {
        Session {
            id: SessionId::new("session-1").unwrap(),
            user_id: UserId::new(42).unwrap(),
            expires_at: Utc::now() + Duration::minutes(5),
            revoked_at: None,
        }
    }

    fn user(main_group: UserRole, permissions: Vec<UserRole>) -> AuthenticatedUser {
        AuthenticatedUser {
            id: 42,
            username: "neo".into(),
            main_group,
            permissions,
            avatar: None,
        }
    }

    fn service(
        session: Result<Option<Session>, io::Error>,
        user: Result<Option<AuthenticatedUser>, io::Error>,
    ) -> JwtAuthenticationService<Verifier, Sessions, Users> {
        JwtAuthenticationService::new(Verifier(Ok(claims())), Sessions(session), Users(user))
    }

    #[tokio::test]
    async fn returns_principal_for_active_session_and_work_group() {
        let expected_user = user(UserRole::Challenger, Vec::new());
        let service = service(Ok(Some(session())), Ok(Some(expected_user.clone())));

        let principal = service.authenticate("token").await.unwrap();

        assert_eq!(principal.user, expected_user);
        assert_eq!(principal.session_id, SessionId::new("session-1").unwrap());
    }

    #[tokio::test]
    async fn rejects_missing_revoked_expired_or_mismatched_session() {
        let valid_user = || Ok(Some(user(UserRole::Challenger, Vec::new())));

        assert_eq!(
            service(Ok(None), valid_user()).authenticate("token").await,
            Err(AuthenticationError::Unauthorized)
        );

        let mut revoked = session();
        revoked.revoked_at = Some(Utc::now());
        assert_eq!(
            service(Ok(Some(revoked)), valid_user())
                .authenticate("token")
                .await,
            Err(AuthenticationError::Unauthorized)
        );

        let mut expired = session();
        expired.expires_at = Utc::now() - Duration::seconds(1);
        assert_eq!(
            service(Ok(Some(expired)), valid_user())
                .authenticate("token")
                .await,
            Err(AuthenticationError::Unauthorized)
        );

        let mut another_user = session();
        another_user.user_id = UserId::new(7).unwrap();
        assert_eq!(
            service(Ok(Some(another_user)), valid_user())
                .authenticate("token")
                .await,
            Err(AuthenticationError::Unauthorized)
        );

        let mut another_session = session();
        another_session.id = SessionId::new("session-2").unwrap();
        assert_eq!(
            service(Ok(Some(another_session)), valid_user())
                .authenticate("token")
                .await,
            Err(AuthenticationError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn rejects_missing_user_and_mismatched_identity() {
        assert_eq!(
            service(Ok(Some(session())), Ok(None))
                .authenticate("token")
                .await,
            Err(AuthenticationError::Unauthorized)
        );

        let mut another_user = user(UserRole::Challenger, Vec::new());
        another_user.id = 7;
        assert_eq!(
            service(Ok(Some(session())), Ok(Some(another_user)))
                .authenticate("token")
                .await,
            Err(AuthenticationError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn accepts_workspace_main_group_without_permission_duplication() {
        for main_group in [
            UserRole::Challenger,
            UserRole::Developer,
            UserRole::Admin,
            UserRole::Mapper,
            UserRole::Configurator,
            UserRole::Backuper,
        ] {
            let expected_user = user(main_group, Vec::new());
            let principal = service(Ok(Some(session())), Ok(Some(expected_user.clone())))
                .authenticate("token")
                .await
                .unwrap();

            assert_eq!(principal.user, expected_user);
        }
    }

    #[tokio::test]
    async fn rejects_token_verification_failure() {
        let service = JwtAuthenticationService::new(
            Verifier(Err(AuthenticationError::Unauthorized)),
            Sessions(Ok(Some(session()))),
            Users(Ok(Some(user(UserRole::Challenger, Vec::new())))),
        );

        assert_eq!(
            service.authenticate("invalid-token").await,
            Err(AuthenticationError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn rejects_subject_that_does_not_fit_legacy_user_id() {
        let mut oversized_claims = claims();
        oversized_claims.sub = UserId::new(i64::MAX).unwrap();
        let mut matching_session = session();
        matching_session.user_id = oversized_claims.sub;
        let service = JwtAuthenticationService::new(
            Verifier(Ok(oversized_claims)),
            Sessions(Ok(Some(matching_session))),
            Users(Ok(Some(user(UserRole::Challenger, Vec::new())))),
        );

        assert_eq!(
            service.authenticate("token").await,
            Err(AuthenticationError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn reports_repository_failures_as_unavailable() {
        let database_error = || io::Error::other("database unavailable");

        assert_eq!(
            service(
                Err(database_error()),
                Ok(Some(user(UserRole::Challenger, Vec::new()))),
            )
            .authenticate("token")
            .await,
            Err(AuthenticationError::Unavailable)
        );
        assert_eq!(
            service(Ok(Some(session())), Err(database_error()))
                .authenticate("token")
                .await,
            Err(AuthenticationError::Unavailable)
        );
    }
}
