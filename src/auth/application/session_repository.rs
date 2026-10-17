use std::{error::Error, future::Future};

use chrono::{DateTime, Utc};

use crate::auth::domain::models::{Session, SessionId};

/// Persistence port for server-side authentication sessions.
pub trait SessionRepository: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn create(&self, session: &Session) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn find_by_id(
        &self,
        session_id: &SessionId,
    ) -> impl Future<Output = Result<Option<Session>, Self::Error>> + Send;

    /// Idempotently revokes a session. Security policies use this when a
    /// previously issued session no longer satisfies the user's protection
    /// level.
    fn revoke(
        &self,
        session_id: &SessionId,
        revoked_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
