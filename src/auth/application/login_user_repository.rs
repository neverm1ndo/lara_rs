use std::{error::Error, future::Future};

use crate::{
    auth::domain::models::{AuthenticatedUser, UserId},
    shared::user_role::UserRole,
};

/// User data required only while checking login credentials.
///
/// Keeping the password hash outside `AuthenticatedUser` prevents it from
/// leaking into session responses or JWT-related code.
#[derive(Clone)]
pub struct LoginUser {
    pub id: UserId,
    pub username: String,
    pub main_group: UserRole,
    pub permissions: Vec<UserRole>,
    pub avatar: Option<String>,
    pub password_hash: String,
}

impl LoginUser {
    pub fn into_authenticated_user(self) -> AuthenticatedUser {
        AuthenticatedUser {
            id: self.id.get(),
            username: self.username,
            main_group: self.main_group,
            permissions: self.permissions,
            avatar: self.avatar,
        }
    }
}

/// Cross-context port used by the authentication application layer.
pub trait LoginUserRepository: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn find_by_email(
        &self,
        email: &str,
    ) -> impl Future<Output = Result<Option<LoginUser>, Self::Error>> + Send;
}
