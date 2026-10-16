use sea_orm::{DatabaseBackend, DatabaseConnection, DbErr, FromQueryResult, Statement};
use thiserror::Error;

use crate::{
    auth::{
        application::login_user_repository::{LoginUser, LoginUserRepository},
        domain::models::{InvalidIdentifier, UserId},
    },
    shared::user_role::{InvalidUserRole, UserRole},
};

const LOGIN_USER_QUERY: &str = r#"
    SELECT
        ug.user_id AS id,
        u.username,
        u.user_password AS password_hash,
        u.user_avatar AS avatar,
        u.group_id AS main_group,
        GROUP_CONCAT(DISTINCT ug.group_id ORDER BY ug.group_id SEPARATOR ',') AS permissions
    FROM phpbb_user_group AS ug
    JOIN phpbb_users AS u
        ON u.user_id = ug.user_id
    WHERE u.user_email = ?
        AND ug.group_id BETWEEN 9 AND 14
    GROUP BY
        u.user_id,
        u.username,
        u.user_password,
        u.user_avatar,
        u.group_id;
"#;

#[derive(FromQueryResult)]
struct LoginUserRow {
    // phpBB declares identifiers as MEDIUMINT UNSIGNED. SQLx deliberately
    // rejects decoding that column into a signed Rust integer.
    id: u32,
    username: String,
    password_hash: String,
    avatar: Option<String>,
    main_group: u32,
    permissions: String,
}

#[derive(Debug, Error)]
pub enum LoginUserRepositoryError {
    #[error("database error")]
    Database(#[from] DbErr),
    #[error("database returned invalid permissions")]
    InvalidPermissions,
    #[error(transparent)]
    InvalidIdentifier(#[from] InvalidIdentifier),
    #[error(transparent)]
    InvalidRole(#[from] InvalidUserRole),
}

#[derive(Clone)]
pub struct SeaOrmLoginUserRepository {
    db: DatabaseConnection,
}

impl SeaOrmLoginUserRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl LoginUserRepository for SeaOrmLoginUserRepository {
    type Error = LoginUserRepositoryError;

    async fn find_by_email(&self, email: &str) -> Result<Option<LoginUser>, Self::Error> {
        let statement = Statement::from_sql_and_values(
            DatabaseBackend::MySql,
            LOGIN_USER_QUERY,
            [email.into()],
        );
        let row = LoginUserRow::find_by_statement(statement)
            .one(&self.db)
            .await?;

        row.map(|row| {
            let user_id = row.id;
            let main_group = row.main_group;

            LoginUser::try_from(row).inspect_err(|error| {
                tracing::error!(
                    error = %error,
                    error_debug = ?error,
                    user_id,
                    main_group,
                    "login user row violates the domain model"
                );
            })
        })
        .transpose()
    }
}

impl TryFrom<LoginUserRow> for LoginUser {
    type Error = LoginUserRepositoryError;

    fn try_from(row: LoginUserRow) -> Result<Self, Self::Error> {
        let permissions = row
            .permissions
            .split(',')
            .map(str::trim)
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| LoginUserRepositoryError::InvalidPermissions)?
            .into_iter()
            .map(UserRole::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let id = UserId::new(i64::from(row.id))?;

        Ok(Self {
            id,
            username: row.username,
            main_group: UserRole::try_from(row.main_group)?,
            permissions,
            avatar: row.avatar,
            password_hash: row.password_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> LoginUserRow {
        LoginUserRow {
            id: 42,
            username: "neo".into(),
            password_hash: "salt0123456789abcdef0123456789abcdef".into(),
            avatar: Some("neo.png".into()),
            main_group: 11,
            permissions: "9,11,14".into(),
        }
    }

    #[test]
    fn maps_login_record_without_putting_hash_in_authenticated_user() {
        let login_user = LoginUser::try_from(row()).unwrap();

        assert_eq!(login_user.id, UserId::new(42).unwrap());
        assert_eq!(login_user.username, "neo");
        assert_eq!(login_user.main_group, UserRole::Admin);
        assert_eq!(
            login_user.permissions,
            vec![UserRole::Challenger, UserRole::Admin, UserRole::Backuper]
        );
        assert_eq!(login_user.avatar.as_deref(), Some("neo.png"));
        assert_eq!(
            login_user.password_hash,
            "salt0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn rejects_invalid_identifier_roles_and_permissions() {
        let mut invalid_id = row();
        invalid_id.id = 0;
        assert!(LoginUser::try_from(invalid_id).is_err());

        let mut invalid_main_group = row();
        invalid_main_group.main_group = 8;
        assert!(LoginUser::try_from(invalid_main_group).is_err());

        let mut invalid_permissions = row();
        invalid_permissions.permissions = "9,nope".into();
        assert!(LoginUser::try_from(invalid_permissions).is_err());

        let mut unknown_permission = row();
        unknown_permission.permissions = "9,15".into();
        assert!(LoginUser::try_from(unknown_permission).is_err());
    }
}
