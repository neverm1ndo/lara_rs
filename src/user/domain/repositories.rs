use std::{error::Error, future::Future};

use super::profile::{UserId, UserProfile};

/// Read-only persistence port for the public workspace-user projection.
///
/// `Ok(None)` means that the user does not exist or is not visible as a
/// workspace user. Infrastructure failures are returned through the adapter's
/// associated error type and translated by the application layer.
pub trait UserProfileRepository: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn find_by_id(
        &self,
        id: UserId,
    ) -> impl Future<Output = Result<Option<UserProfile>, Self::Error>> + Send;
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, future};

    use crate::shared::user_role::UserRole;

    use super::*;

    struct InMemoryUsers(Option<UserProfile>);

    impl UserProfileRepository for InMemoryUsers {
        type Error = Infallible;

        fn find_by_id(
            &self,
            id: UserId,
        ) -> impl Future<Output = Result<Option<UserProfile>, Self::Error>> + Send {
            let profile = self
                .0
                .as_ref()
                .filter(|profile| profile.id() == id)
                .cloned();
            future::ready(Ok(profile))
        }
    }

    fn profile() -> UserProfile {
        UserProfile::new(
            UserId::new(42).unwrap(),
            "neo",
            None,
            UserRole::Admin,
            vec![UserRole::Admin],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn repository_contract_distinguishes_found_and_missing_users() {
        let repository = InMemoryUsers(Some(profile()));

        assert_eq!(
            repository
                .find_by_id(UserId::new(42).unwrap())
                .await
                .unwrap(),
            Some(profile())
        );
        assert_eq!(
            repository
                .find_by_id(UserId::new(7).unwrap())
                .await
                .unwrap(),
            None
        );
    }
}
