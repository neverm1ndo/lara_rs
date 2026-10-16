use crate::shared::user_role::UserRole;

pub fn is_user_in_work_group(permissions: &[UserRole]) -> bool {
    permissions
        .iter()
        .copied()
        .any(UserRole::grants_workspace_access)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_at_least_one_workspace_role() {
        assert!(!is_user_in_work_group(&[]));
        assert!(is_user_in_work_group(&[UserRole::Developer]));
    }
}
