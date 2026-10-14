pub use crate::shared::user_role::UserRole;
use crate::user::domain::exception::UserError;

#[derive(Debug, Clone)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password: String,
    pub email: String,
    pub avatar: Option<String>,
    pub main_group: UserRole,
    pub permissions: Vec<UserRole>,
}

impl User {
    pub fn new(username: String, plain_password: &str, email: String) -> Result<Self, UserError> {
        let _ = (username, plain_password, email);
        todo!("user creation is not implemented yet")
    }
}
