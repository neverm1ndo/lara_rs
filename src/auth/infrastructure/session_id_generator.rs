use uuid::Uuid;

use crate::auth::{
    application::session_id_generator::SessionIdGenerator, domain::models::SessionId,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct UuidSessionIdGenerator;

impl SessionIdGenerator for UuidSessionIdGenerator {
    fn generate(&self) -> SessionId {
        SessionId::new(Uuid::new_v4().to_string())
            .expect("a UUID session identifier is always non-empty")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_unique_uuid_v4_session_ids() {
        let first = UuidSessionIdGenerator.generate();
        let second = UuidSessionIdGenerator.generate();

        assert_ne!(first, second);
        assert_eq!(
            Uuid::parse_str(first.as_str()).unwrap().get_version_num(),
            4
        );
        assert_eq!(
            Uuid::parse_str(second.as_str()).unwrap().get_version_num(),
            4
        );
    }
}
