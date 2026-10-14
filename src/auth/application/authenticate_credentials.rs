use thiserror::Error;

use crate::auth::{
    application::{
        login_user_repository::LoginUserRepository, password_verifier::PasswordVerifier,
    },
    domain::{
        models::{AuthenticatedUser, UserId},
        rules::is_user_in_work_group,
    },
};

const MAX_EMAIL_LENGTH: usize = 254;
const MAX_PASSWORD_LENGTH: usize = 1_024;
// Structurally valid legacy hash used when the email does not exist. The
// result is always ignored; its purpose is to keep the password-hash branch.
const DUMMY_PASSWORD_HASH: &str = "dummy-salt00000000000000000000000000000000";

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum CredentialAuthenticationError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("authentication dependency is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCredentials {
    pub user_id: UserId,
    pub user: AuthenticatedUser,
}

pub struct CredentialAuthenticationService<P, U> {
    password_verifier: P,
    users: U,
}

impl<P, U> CredentialAuthenticationService<P, U> {
    pub fn new(password_verifier: P, users: U) -> Self {
        Self {
            password_verifier,
            users,
        }
    }
}

impl<P, U> CredentialAuthenticationService<P, U>
where
    P: PasswordVerifier,
    U: LoginUserRepository,
{
    pub async fn authenticate(
        &self,
        email: &str,
        password: &str,
    ) -> Result<VerifiedCredentials, CredentialAuthenticationError> {
        if !valid_credentials_shape(email, password) {
            return Err(CredentialAuthenticationError::InvalidCredentials);
        }

        let Some(login_user) = self.users.find_by_email(email).await.map_err(|error| {
            tracing::error!(
                error = %error,
                error_debug = ?error,
                "failed to load login user"
            );
            CredentialAuthenticationError::Unavailable
        })?
        else {
            let _ = self.password_verifier.verify(password, DUMMY_PASSWORD_HASH);
            return Err(CredentialAuthenticationError::InvalidCredentials);
        };

        if !self
            .password_verifier
            .verify(password, &login_user.password_hash)
            || !is_user_in_work_group(&login_user.permissions)
        {
            return Err(CredentialAuthenticationError::InvalidCredentials);
        }

        let user_id = login_user.id;
        Ok(VerifiedCredentials {
            user_id,
            user: login_user.into_authenticated_user(),
        })
    }
}

fn valid_credentials_shape(email: &str, password: &str) -> bool {
    !email.trim().is_empty()
        && email.len() <= MAX_EMAIL_LENGTH
        && !password.is_empty()
        && password.len() <= MAX_PASSWORD_LENGTH
}

#[cfg(test)]
mod tests {
    use std::{
        future, io,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use crate::{auth::application::login_user_repository::LoginUser, shared::user_role::UserRole};

    use super::*;

    #[derive(Clone)]
    enum UserResult {
        Found(LoginUser),
        Missing,
        Failed,
    }

    struct Users(UserResult);

    impl LoginUserRepository for Users {
        type Error = io::Error;

        fn find_by_email(
            &self,
            _email: &str,
        ) -> impl Future<Output = Result<Option<LoginUser>, Self::Error>> + Send {
            future::ready(match &self.0 {
                UserResult::Found(user) => Ok(Some(user.clone())),
                UserResult::Missing => Ok(None),
                UserResult::Failed => Err(io::Error::other("database unavailable")),
            })
        }
    }

    #[derive(Clone, Default)]
    struct Passwords {
        calls: Arc<AtomicUsize>,
    }

    impl PasswordVerifier for Passwords {
        fn verify(&self, password: &str, stored_hash: &str) -> bool {
            self.calls.fetch_add(1, Ordering::Relaxed);
            password == "correct" && stored_hash == "stored-hash"
        }
    }

    fn login_user(permissions: Vec<UserRole>) -> LoginUser {
        LoginUser {
            id: UserId::new(42).unwrap(),
            username: "neo".into(),
            main_group: UserRole::ADMIN,
            permissions,
            avatar: None,
            password_hash: "stored-hash".into(),
        }
    }

    #[tokio::test]
    async fn authenticates_valid_credentials_and_returns_safe_user() {
        let service = CredentialAuthenticationService::new(
            Passwords::default(),
            Users(UserResult::Found(login_user(vec![UserRole::ADMIN]))),
        );

        let verified = service
            .authenticate("neo@example.com", "correct")
            .await
            .unwrap();

        assert_eq!(verified.user_id, UserId::new(42).unwrap());
        assert_eq!(verified.user.id, 42);
        assert_eq!(verified.user.username, "neo");
        assert_eq!(verified.user.permissions, vec![UserRole::ADMIN]);
    }

    #[tokio::test]
    async fn hides_missing_user_wrong_password_and_missing_work_group() {
        let missing_passwords = Passwords::default();
        let missing_service = CredentialAuthenticationService::new(
            missing_passwords.clone(),
            Users(UserResult::Missing),
        );
        assert_eq!(
            missing_service
                .authenticate("missing@example.com", "anything")
                .await,
            Err(CredentialAuthenticationError::InvalidCredentials)
        );
        assert_eq!(missing_passwords.calls.load(Ordering::Relaxed), 1);

        let wrong_password = CredentialAuthenticationService::new(
            Passwords::default(),
            Users(UserResult::Found(login_user(vec![UserRole::ADMIN]))),
        );
        assert_eq!(
            wrong_password
                .authenticate("neo@example.com", "wrong")
                .await,
            Err(CredentialAuthenticationError::InvalidCredentials)
        );

        let no_work_group = CredentialAuthenticationService::new(
            Passwords::default(),
            Users(UserResult::Found(login_user(Vec::new()))),
        );
        assert_eq!(
            no_work_group
                .authenticate("neo@example.com", "correct")
                .await,
            Err(CredentialAuthenticationError::InvalidCredentials)
        );
    }

    #[tokio::test]
    async fn rejects_missing_or_oversized_credentials_before_repository_lookup() {
        for (email, password) in [
            (String::new(), "correct".to_owned()),
            ("   ".to_owned(), "correct".to_owned()),
            ("neo@example.com".to_owned(), String::new()),
            ("e".repeat(MAX_EMAIL_LENGTH + 1), "correct".to_owned()),
            (
                "neo@example.com".to_owned(),
                "p".repeat(MAX_PASSWORD_LENGTH + 1),
            ),
        ] {
            let service = CredentialAuthenticationService::new(
                Passwords::default(),
                Users(UserResult::Failed),
            );

            assert_eq!(
                service.authenticate(&email, &password).await,
                Err(CredentialAuthenticationError::InvalidCredentials)
            );
        }
    }

    #[tokio::test]
    async fn maps_repository_failure_to_unavailable() {
        let service =
            CredentialAuthenticationService::new(Passwords::default(), Users(UserResult::Failed));

        assert_eq!(
            service.authenticate("neo@example.com", "correct").await,
            Err(CredentialAuthenticationError::Unavailable)
        );
    }
}
