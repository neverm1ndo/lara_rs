use serde::Serialize;
use utoipa::ToSchema;

use crate::user::domain::profile::UserProfile;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    pub id: i64,
    pub username: String,
    pub avatar: Option<String>,
    pub main_group: i32,
    pub permissions: Vec<i32>,
}

impl From<UserProfile> for UserResponse {
    fn from(profile: UserProfile) -> Self {
        Self {
            id: profile.id().get(),
            username: profile.username().to_owned(),
            avatar: profile.avatar().map(str::to_owned),
            main_group: profile.main_group().as_i32(),
            permissions: profile
                .permissions()
                .iter()
                .copied()
                .map(i32::from)
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserErrorResponse {
    pub code: &'static str,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{shared::user_role::UserRole, user::domain::profile::UserId};

    use super::*;

    #[test]
    fn serializes_safe_profile_in_camel_case() {
        let response = UserResponse::from(
            UserProfile::new(
                UserId::new(42).unwrap(),
                "neo",
                Some("neo.png".into()),
                UserRole::ADMIN,
                vec![UserRole::CHALLENGER, UserRole::ADMIN],
            )
            .unwrap(),
        );

        let value = serde_json::to_value(response).unwrap();

        assert_eq!(value["id"], 42);
        assert_eq!(value["username"], "neo");
        assert_eq!(value["avatar"], "neo.png");
        assert_eq!(value["mainGroup"], 11);
        assert_eq!(value["permissions"], json!([9, 11]));
        assert!(value.get("email").is_none());
        assert!(value.get("password").is_none());
        assert!(value.get("sessionId").is_none());
    }
}
