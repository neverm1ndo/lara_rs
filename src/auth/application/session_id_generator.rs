use crate::auth::domain::models::SessionId;

pub trait SessionIdGenerator: Send + Sync {
    fn generate(&self) -> SessionId;
}
