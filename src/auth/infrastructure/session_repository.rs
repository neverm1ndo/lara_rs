use std::time::Duration;

use chrono::{DateTime, Utc};
use mongodb::{
    Collection, Database, IndexModel,
    bson::{DateTime as BsonDateTime, doc},
    options::IndexOptions,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::auth::{
    application::session_repository::SessionRepository,
    domain::models::{InvalidIdentifier, Session, SessionId, UserId},
};

const SESSION_COLLECTION: &str = "auth_sessions";

/// MongoDB representation. The `_id` index is used for every authentication
/// lookup; `expires_at` must remain a BSON date for the TTL index to work.
#[derive(Debug, Deserialize, Serialize)]
struct SessionDocument {
    #[serde(rename = "_id")]
    id: String,
    user_id: i64,
    expires_at: BsonDateTime,
    #[serde(default)]
    revoked_at: Option<BsonDateTime>,
}

#[derive(Debug, Error)]
pub enum SessionRepositoryError {
    #[error("MongoDB error")]
    Database(#[from] mongodb::error::Error),
    #[error("database returned an invalid session identifier")]
    InvalidIdentifier(#[from] InvalidIdentifier),
    #[error("database returned an invalid session timestamp")]
    InvalidTimestamp,
}

#[derive(Clone)]
pub struct MongoSessionRepository {
    sessions: Collection<SessionDocument>,
}

impl MongoSessionRepository {
    pub fn new(database: Database) -> Self {
        Self {
            sessions: database.collection(SESSION_COLLECTION),
        }
    }

    /// Creates the indexes required by the session store.
    ///
    /// MongoDB's `_id` index already handles lookups by `SessionId`. The TTL
    /// index is cleanup only: callers must still use `Session::is_active`
    /// because MongoDB removes expired documents asynchronously.
    pub async fn ensure_indexes(&self) -> Result<(), SessionRepositoryError> {
        let ttl = IndexModel::builder()
            .keys(doc! { "expires_at": 1 })
            .options(
                IndexOptions::builder()
                    .name(Some("auth_sessions_expires_at_ttl".to_owned()))
                    .expire_after(Some(Duration::ZERO))
                    .build(),
            )
            .build();
        let by_user = IndexModel::builder()
            .keys(doc! { "user_id": 1 })
            .options(
                IndexOptions::builder()
                    .name(Some("auth_sessions_user_id".to_owned()))
                    .build(),
            )
            .build();

        self.sessions.create_indexes([ttl, by_user]).await?;
        Ok(())
    }
}

impl SessionRepository for MongoSessionRepository {
    type Error = SessionRepositoryError;

    async fn create(&self, session: &Session) -> Result<(), Self::Error> {
        self.sessions
            .insert_one(SessionDocument::from(session))
            .await?;
        Ok(())
    }

    async fn find_by_id(&self, session_id: &SessionId) -> Result<Option<Session>, Self::Error> {
        // MongoDB uses primary reads by default. Keep that behavior for
        // security-sensitive session revocation checks.
        let document = self
            .sessions
            .find_one(doc! { "_id": session_id.as_str() })
            .await?;

        document.map(TryInto::try_into).transpose()
    }
}

impl From<&Session> for SessionDocument {
    fn from(session: &Session) -> Self {
        Self {
            id: session.id.as_str().to_owned(),
            user_id: session.user_id.get(),
            expires_at: BsonDateTime::from_millis(session.expires_at.timestamp_millis()),
            revoked_at: session
                .revoked_at
                .map(|value| BsonDateTime::from_millis(value.timestamp_millis())),
        }
    }
}

impl TryFrom<SessionDocument> for Session {
    type Error = SessionRepositoryError;

    fn try_from(document: SessionDocument) -> Result<Self, Self::Error> {
        Ok(Self {
            id: SessionId::new(document.id)?,
            user_id: UserId::new(document.user_id)?,
            expires_at: from_bson_datetime(document.expires_at)?,
            revoked_at: document.revoked_at.map(from_bson_datetime).transpose()?,
        })
    }
}

fn from_bson_datetime(value: BsonDateTime) -> Result<DateTime<Utc>, SessionRepositoryError> {
    DateTime::from_timestamp_millis(value.timestamp_millis())
        .ok_or(SessionRepositoryError::InvalidTimestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_mongo_document_to_domain_session() {
        let document = SessionDocument {
            id: "session-1".into(),
            user_id: 42,
            expires_at: BsonDateTime::from_millis(2_000_000),
            revoked_at: None,
        };

        let session = Session::try_from(document).unwrap();

        assert_eq!(session.id, SessionId::new("session-1").unwrap());
        assert_eq!(session.user_id, UserId::new(42).unwrap());
        assert_eq!(session.expires_at.timestamp_millis(), 2_000_000);
        assert_eq!(session.revoked_at, None);
    }

    #[test]
    fn maps_domain_session_to_mongo_document() {
        let session = Session {
            id: SessionId::new("session-1").unwrap(),
            user_id: UserId::new(42).unwrap(),
            expires_at: DateTime::from_timestamp_millis(2_000_000).unwrap(),
            revoked_at: Some(DateTime::from_timestamp_millis(1_000_000).unwrap()),
        };

        let document = SessionDocument::from(&session);

        assert_eq!(document.id, "session-1");
        assert_eq!(document.user_id, 42);
        assert_eq!(document.expires_at.timestamp_millis(), 2_000_000);
        assert_eq!(document.revoked_at.unwrap().timestamp_millis(), 1_000_000);
    }

    #[test]
    fn maps_revocation_timestamp() {
        let document = SessionDocument {
            id: "session-1".into(),
            user_id: 42,
            expires_at: BsonDateTime::from_millis(2_000_000),
            revoked_at: Some(BsonDateTime::from_millis(1_000_000)),
        };

        let session = Session::try_from(document).unwrap();

        assert_eq!(session.revoked_at.unwrap().timestamp_millis(), 1_000_000);
    }

    #[test]
    fn rejects_invalid_identifiers_from_mongo() {
        let document = SessionDocument {
            id: String::new(),
            user_id: 0,
            expires_at: BsonDateTime::from_millis(2_000_000),
            revoked_at: None,
        };

        assert!(Session::try_from(document).is_err());
    }

    #[test]
    fn rejects_timestamp_outside_chrono_range() {
        let document = SessionDocument {
            id: "session-1".into(),
            user_id: 42,
            expires_at: BsonDateTime::from_millis(i64::MAX),
            revoked_at: None,
        };

        assert!(matches!(
            Session::try_from(document),
            Err(SessionRepositoryError::InvalidTimestamp)
        ));
    }
}
