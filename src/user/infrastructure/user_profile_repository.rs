use sea_orm::{DatabaseBackend, DatabaseConnection, DbErr, FromQueryResult, Statement};
use thiserror::Error;

use crate::{
    shared::user_role::{InvalidUserRole, UserRole},
    user::domain::{
        exception::{InvalidUserId, InvalidUserProfile},
        profile::{UserId, UserProfile},
        repositories::UserProfileRepository,
    },
};

const USER_PROFILE_QUERY: &str = r#"
    SELECT
        ug.user_id AS id,
        u.username,
        u.user_avatar AS avatar,
        u.group_id AS main_group,
        GROUP_CONCAT(DISTINCT ug.group_id ORDER BY ug.group_id SEPARATOR ',') AS permissions
    FROM phpbb_user_group AS ug
    JOIN phpbb_users AS u
        ON u.user_id = ug.user_id
    WHERE ug.user_id = ?
        AND ug.group_id BETWEEN 9 AND 14
    GROUP BY
        u.user_id,
        u.username,
        u.user_avatar,
        u.group_id;
"#;

#[derive(Debug, FromQueryResult)]
struct UserProfileRow {
    // phpBB identifiers are MEDIUMINT UNSIGNED. Decode them without a signed
    // intermediate and widen only when entering the domain model.
    id: u32,
    username: String,
    avatar: Option<String>,
    main_group: u32,
    permissions: String,
}

#[derive(Debug, Error)]
pub enum UserProfileRepositoryError {
    #[error("database error")]
    Database(#[from] DbErr),
    #[error("database returned malformed permissions")]
    InvalidPermissions,
    #[error(transparent)]
    InvalidIdentifier(#[from] InvalidUserId),
    #[error(transparent)]
    InvalidRole(#[from] InvalidUserRole),
    #[error(transparent)]
    InvalidProfile(#[from] InvalidUserProfile),
}

#[derive(Clone)]
pub struct SeaOrmUserProfileRepository {
    db: DatabaseConnection,
}

impl SeaOrmUserProfileRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl UserProfileRepository for SeaOrmUserProfileRepository {
    type Error = UserProfileRepositoryError;

    async fn find_by_id(&self, id: UserId) -> Result<Option<UserProfile>, Self::Error> {
        let statement = Statement::from_sql_and_values(
            DatabaseBackend::MySql,
            USER_PROFILE_QUERY,
            [id.get().into()],
        );
        let row = UserProfileRow::find_by_statement(statement)
            .one(&self.db)
            .await?;

        row.map(TryInto::try_into).transpose()
    }
}

impl TryFrom<UserProfileRow> for UserProfile {
    type Error = UserProfileRepositoryError;

    fn try_from(row: UserProfileRow) -> Result<Self, Self::Error> {
        let permissions = row
            .permissions
            .split(',')
            .map(str::trim)
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| UserProfileRepositoryError::InvalidPermissions)?
            .into_iter()
            .map(UserRole::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(UserProfile::new(
            UserId::new(i64::from(row.id))?,
            row.username,
            row.avatar,
            UserRole::try_from(row.main_group)?,
            permissions,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> UserProfileRow {
        UserProfileRow {
            id: 42,
            username: "neo".into(),
            avatar: Some("neo.png".into()),
            main_group: 11,
            permissions: "9,11,14".into(),
        }
    }

    #[test]
    fn maps_phpbb_row_to_safe_domain_profile() {
        let profile = UserProfile::try_from(row()).unwrap();

        assert_eq!(profile.id(), UserId::new(42).unwrap());
        assert_eq!(profile.username(), "neo");
        assert_eq!(profile.avatar(), Some("neo.png"));
        assert_eq!(profile.main_group(), UserRole::ADMIN);
        assert_eq!(
            profile.permissions(),
            &[UserRole::CHALLENGER, UserRole::ADMIN, UserRole::BACKUPER]
        );
    }

    #[test]
    fn rejects_malformed_or_unknown_permissions() {
        let mut malformed = row();
        malformed.permissions = "9,nope".into();
        assert!(matches!(
            UserProfile::try_from(malformed),
            Err(UserProfileRepositoryError::InvalidPermissions)
        ));

        let mut unknown = row();
        unknown.permissions = "9,11,15".into();
        assert!(matches!(
            UserProfile::try_from(unknown),
            Err(UserProfileRepositoryError::InvalidRole(_))
        ));
    }

    #[test]
    fn rejects_invalid_identifier_main_group_and_profile_invariants() {
        let mut invalid_id = row();
        invalid_id.id = 0;
        assert!(matches!(
            UserProfile::try_from(invalid_id),
            Err(UserProfileRepositoryError::InvalidIdentifier(_))
        ));

        let mut invalid_main_group = row();
        invalid_main_group.main_group = 8;
        assert!(matches!(
            UserProfile::try_from(invalid_main_group),
            Err(UserProfileRepositoryError::InvalidRole(_))
        ));

        let mut inconsistent = row();
        inconsistent.permissions = "9,14".into();
        assert!(matches!(
            UserProfile::try_from(inconsistent),
            Err(UserProfileRepositoryError::InvalidProfile(
                InvalidUserProfile::MainGroupNotGranted(UserRole::ADMIN)
            ))
        ));
    }
}
