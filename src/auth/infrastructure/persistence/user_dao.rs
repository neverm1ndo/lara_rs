use sea_orm::{ConnectionTrait, DatabaseBackend, FromQueryResult, Statement, DbErr};

#[derive(FromQueryResult, Debug)]
pub struct PhpBbUserRow {
    pub id: u32,
    pub username: String,
    pub avatar: Option<String>,
    pub main_group: u32,
    pub permissions: String, // Строка из GROUP_CONCAT (например, "9,10,11")
    pub email: String,
}

const JWT_USER_QUERY: &str = "
    SELECT 
        u.user_id AS id,
        u.username,
        u.user_avatar AS avatar,
        u.group_id AS main_group,
        GROUP_CONCAT(DISTINCT ug.group_id ORDER BY ug.group_id SEPARATOR ',') AS permissions,
        u.user_email AS email
    FROM phpbb_user_group AS ug
    JOIN phpbb_users AS u 
        ON u.user_id = ug.user_id
    WHERE ug.user_id = ?
        AND ug.group_id BETWEEN 9 AND 14
    GROUP BY 
        u.user_id, 
        u.username, 
        u.user_avatar, 
        u.group_id, 
        u.user_email;
";

pub async fn fetch_user_permissions<C>(db: &C, user_id: u32) -> Result<Option<PhpBbUserRow>, DbErr>
where
    C: ConnectionTrait,
{
    let stmt = Statement::from_sql_and_values(
        DatabaseBackend::MySql,
        JWT_USER_QUERY,
        [user_id.into()],
    );

    PhpBbUserRow::find_by_statement(stmt).one(db).await
}
