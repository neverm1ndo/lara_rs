use crate::{
    shared::user_role::UserRole,
    user::domain::exception::{InvalidUserId, InvalidUserProfile},
};

/// Stable identifier of a phpBB user exposed within the user context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserId(i64);

impl UserId {
    pub fn new(value: i64) -> Result<Self, InvalidUserId> {
        (value > 0).then_some(Self(value)).ok_or(InvalidUserId)
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Safe read-only projection of a workspace user.
///
/// Authentication credentials, email and session data deliberately do not
/// belong to this model and cannot accidentally leak through the user API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserProfile {
    id: UserId,
    username: String,
    avatar: Option<String>,
    main_group: UserRole,
    permissions: Vec<UserRole>,
}

impl UserProfile {
    pub fn new(
        id: UserId,
        username: impl Into<String>,
        avatar: Option<String>,
        main_group: UserRole,
        permissions: Vec<UserRole>,
    ) -> Result<Self, InvalidUserProfile> {
        let username = username.into();
        if username.trim().is_empty() {
            return Err(InvalidUserProfile::EmptyUsername);
        }
        if permissions.is_empty() {
            return Err(InvalidUserProfile::EmptyPermissions);
        }
        if !permissions.contains(&main_group) {
            return Err(InvalidUserProfile::MainGroupNotGranted(main_group));
        }

        for (index, permission) in permissions.iter().enumerate() {
            if permissions[index + 1..].contains(permission) {
                return Err(InvalidUserProfile::DuplicatePermission(*permission));
            }
        }

        Ok(Self {
            id,
            username,
            avatar,
            main_group,
            permissions,
        })
    }

    pub const fn id(&self) -> UserId {
        self.id
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn avatar(&self) -> Option<&str> {
        self.avatar.as_deref()
    }

    pub const fn main_group(&self) -> UserRole {
        self.main_group
    }

    pub fn permissions(&self) -> &[UserRole] {
        &self.permissions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(
        main_group: UserRole,
        permissions: Vec<UserRole>,
    ) -> Result<UserProfile, InvalidUserProfile> {
        UserProfile::new(
            UserId::new(42).unwrap(),
            "neo",
            Some("neo.png".into()),
            main_group,
            permissions,
        )
    }

    #[test]
    fn user_id_accepts_only_positive_values() {
        assert_eq!(UserId::new(42).unwrap().get(), 42);
        assert_eq!(UserId::new(0), Err(InvalidUserId));
        assert_eq!(UserId::new(-1), Err(InvalidUserId));
    }

    #[test]
    fn creates_safe_profile_for_every_workspace_role() {
        for role in [
            UserRole::CHALLENGER,
            UserRole::DEVELOPER,
            UserRole::ADMIN,
            UserRole::MAPPER,
            UserRole::CONFIGURATOR,
            UserRole::BACKUPER,
        ] {
            let profile = profile(role, vec![role]).unwrap();

            assert_eq!(profile.id().get(), 42);
            assert_eq!(profile.username(), "neo");
            assert_eq!(profile.avatar(), Some("neo.png"));
            assert_eq!(profile.main_group(), role);
            assert_eq!(profile.permissions(), &[role]);
        }
    }

    #[test]
    fn rejects_blank_username() {
        let result = UserProfile::new(
            UserId::new(42).unwrap(),
            "  ",
            None,
            UserRole::ADMIN,
            vec![UserRole::ADMIN],
        );

        assert_eq!(result, Err(InvalidUserProfile::EmptyUsername));
    }

    #[test]
    fn rejects_empty_permissions() {
        assert_eq!(
            profile(UserRole::ADMIN, vec![]),
            Err(InvalidUserProfile::EmptyPermissions)
        );
    }

    #[test]
    fn rejects_main_group_missing_from_permissions() {
        assert_eq!(
            profile(UserRole::ADMIN, vec![UserRole::DEVELOPER]),
            Err(InvalidUserProfile::MainGroupNotGranted(UserRole::ADMIN))
        );
    }

    #[test]
    fn rejects_duplicate_permissions() {
        assert_eq!(
            profile(
                UserRole::ADMIN,
                vec![UserRole::ADMIN, UserRole::DEVELOPER, UserRole::ADMIN],
            ),
            Err(InvalidUserProfile::DuplicatePermission(UserRole::ADMIN))
        );
    }
}
