use std::{future::Future, pin::Pin};

use thiserror::Error;

use crate::user::domain::{
    profile::{UserId, UserProfile},
    repositories::UserProfileRepository,
};

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum GetUserError {
    #[error("user not found")]
    NotFound,
    #[error("user service is unavailable")]
    Unavailable,
}

/// Object-safe application boundary consumed by the HTTP presentation layer.
pub trait GetUser: Send + Sync {
    fn get_user(
        &self,
        id: UserId,
    ) -> Pin<Box<dyn Future<Output = Result<UserProfile, GetUserError>> + Send + '_>>;
}

pub struct GetUserService<R> {
    repository: R,
}

impl<R> GetUserService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }
}

impl<R> GetUserService<R>
where
    R: UserProfileRepository,
{
    pub async fn execute(&self, id: UserId) -> Result<UserProfile, GetUserError> {
        self.repository
            .find_by_id(id)
            .await
            .map_err(|error| {
                tracing::error!(
                    error = %error,
                    error_debug = ?error,
                    user_id = id.get(),
                    "failed to load user profile"
                );
                GetUserError::Unavailable
            })?
            .ok_or(GetUserError::NotFound)
    }
}

impl<R> GetUser for GetUserService<R>
where
    R: UserProfileRepository,
{
    fn get_user(
        &self,
        id: UserId,
    ) -> Pin<Box<dyn Future<Output = Result<UserProfile, GetUserError>> + Send + '_>> {
        Box::pin(self.execute(id))
    }
}

#[cfg(test)]
mod tests {
    use std::{future, io, sync::Arc};

    use crate::shared::user_role::UserRole;

    use super::*;

    enum RepositoryResult {
        Found(UserProfile),
        Missing,
        Failed,
    }

    struct Users(RepositoryResult);

    impl UserProfileRepository for Users {
        type Error = io::Error;

        fn find_by_id(
            &self,
            _id: UserId,
        ) -> impl Future<Output = Result<Option<UserProfile>, Self::Error>> + Send {
            future::ready(match &self.0 {
                RepositoryResult::Found(profile) => Ok(Some(profile.clone())),
                RepositoryResult::Missing => Ok(None),
                RepositoryResult::Failed => Err(io::Error::other("database unavailable")),
            })
        }
    }

    fn id() -> UserId {
        UserId::new(42).unwrap()
    }

    fn profile() -> UserProfile {
        UserProfile::new(
            id(),
            "neo",
            Some("neo.png".into()),
            UserRole::ADMIN,
            vec![UserRole::CHALLENGER, UserRole::ADMIN],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn returns_profile_through_object_safe_boundary() {
        let expected = profile();
        let service: Arc<dyn GetUser> = Arc::new(GetUserService::new(Users(
            RepositoryResult::Found(expected.clone()),
        )));

        assert_eq!(service.get_user(id()).await, Ok(expected));
    }

    #[tokio::test]
    async fn reports_missing_profile_as_not_found() {
        let service = GetUserService::new(Users(RepositoryResult::Missing));

        assert_eq!(service.execute(id()).await, Err(GetUserError::NotFound));
    }

    #[tokio::test]
    async fn hides_repository_failure_behind_unavailable_error() {
        let service = GetUserService::new(Users(RepositoryResult::Failed));

        assert_eq!(service.execute(id()).await, Err(GetUserError::Unavailable));
    }
}
