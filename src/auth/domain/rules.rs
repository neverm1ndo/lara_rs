use crate::shared::user_role::UserRole;

/// Determines workspace membership without relying on the persistence detail
/// that the current phpBB query also includes `main_group` in `permissions`.
pub fn is_user_in_work_group(main_group: UserRole, permissions: &[UserRole]) -> bool {
    main_group.grants_workspace_access()
        || permissions
            .iter()
            .copied()
            .any(UserRole::grants_workspace_access)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_every_workspace_role_as_main_group_without_permissions() {
        for main_group in [
            UserRole::Challenger,
            UserRole::Developer,
            UserRole::Admin,
            UserRole::Mapper,
            UserRole::Configurator,
            UserRole::Backuper,
        ] {
            assert!(is_user_in_work_group(main_group, &[]));
        }
    }

    #[test]
    fn does_not_depend_on_main_group_being_duplicated_in_permissions() {
        assert_eq!(
            is_user_in_work_group(UserRole::Admin, &[]),
            is_user_in_work_group(UserRole::Admin, &[UserRole::Admin])
        );
    }
}
