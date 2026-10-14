use std::{error::Error, future::Future};

use crate::auth::domain::models::{Session, SessionId};

/// Persistence port for server-side authentication sessions.
pub trait SessionRepository: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn create(&self, session: &Session) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn find_by_id(
        &self,
        session_id: &SessionId,
    ) -> impl Future<Output = Result<Option<Session>, Self::Error>> + Send;
}
