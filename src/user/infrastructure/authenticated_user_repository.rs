use sea_orm::{DatabaseBackend, DatabaseConnection, DbErr, FromQueryResult, Statement};
use thiserror::Error;

use crate::auth::{
    application::authenticate_jwt::AuthenticatedUserRepository, domain::models::AuthenticatedUser,
};
use crate::shared::user_role::{InvalidUserRole, UserRole};

const JWT_USER_QUERY: &str = r#"
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
struct AuthenticatedUserRow {
    // phpBB declares identifiers as MEDIUMINT UNSIGNED. Keep the SQL
    // projection unsigned and convert only at the domain boundary.
    id: u32,
    username: String,
    avatar: Option<String>,
    main_group: u32,
    permissions: String,
}

#[derive(Debug, Error)]
pub enum AuthenticatedUserRepositoryError {
    #[error("database error")]
    Database(#[from] DbErr),
    #[error("database returned invalid permissions")]
    InvalidPermissions,
    #[error(transparent)]
    InvalidRole(#[from] InvalidUserRole),
}

#[derive(Clone)]
pub struct SeaOrmAuthenticatedUserRepository {
    db: DatabaseConnection,
}

impl SeaOrmAuthenticatedUserRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl AuthenticatedUserRepository for SeaOrmAuthenticatedUserRepository {
    type Error = AuthenticatedUserRepositoryError;

    async fn find_by_id(&self, user_id: i32) -> Result<Option<AuthenticatedUser>, Self::Error> {
        let statement = Statement::from_sql_and_values(
            DatabaseBackend::MySql,
            JWT_USER_QUERY,
            [user_id.into()],
        );
        let row = AuthenticatedUserRow::find_by_statement(statement)
            .one(&self.db)
            .await?;

        row.map(TryInto::try_into).transpose()
    }
}

impl TryFrom<AuthenticatedUserRow> for AuthenticatedUser {
    type Error = AuthenticatedUserRepositoryError;

    fn try_from(row: AuthenticatedUserRow) -> Result<Self, Self::Error> {
        let permissions = row
            .permissions
            .split(',')
            .map(str::trim)
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AuthenticatedUserRepositoryError::InvalidPermissions)?
            .into_iter()
            .map(UserRole::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            id: i64::from(row.id),
            username: row.username,
            main_group: UserRole::try_from(row.main_group)?,
            permissions,
            avatar: row.avatar,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_group_concat_permissions() {
        let row = AuthenticatedUserRow {
            id: 42,
            username: "neo".into(),
            avatar: None,
            main_group: 9,
            permissions: "9,11,14".into(),
        };

        let user = AuthenticatedUser::try_from(row).unwrap();

        assert_eq!(
            user.permissions,
            vec![UserRole::CHALLENGER, UserRole::ADMIN, UserRole::BACKUPER]
        );
    }

    #[test]
    fn rejects_malformed_group_concat_permissions() {
        let row = AuthenticatedUserRow {
            id: 42,
            username: "neo".into(),
            avatar: None,
            main_group: 9,
            permissions: "9,nope".into(),
        };

        assert!(AuthenticatedUser::try_from(row).is_err());
    }

    #[test]
    fn rejects_unknown_main_group_or_permission() {
        let unknown_main_group = AuthenticatedUserRow {
            id: 42,
            username: "neo".into(),
            avatar: None,
            main_group: 8,
            permissions: "9".into(),
        };
        assert!(AuthenticatedUser::try_from(unknown_main_group).is_err());

        let unknown_permission = AuthenticatedUserRow {
            id: 42,
            username: "neo".into(),
            avatar: None,
            main_group: 9,
            permissions: "9,15".into(),
        };
        assert!(AuthenticatedUser::try_from(unknown_permission).is_err());
    }
}
