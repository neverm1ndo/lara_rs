use chrono::{DateTime, Utc};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use std::fmt;
use thiserror::Error;

use crate::shared::user_role::UserRole;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId(i64);

impl UserId {
    pub fn new(value: i64) -> Result<Self, InvalidIdentifier> {
        (value > 0)
            .then_some(Self(value))
            .ok_or(InvalidIdentifier::UserId)
    }

    pub fn get(self) -> i64 {
        self.0
    }
}

// JWT `sub` is a StringOrURI according to RFC 7519. Numeric legacy `id`
// values are accepted on deserialization during the migration period.
impl Serialize for UserId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for UserId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UserIdVisitor;

        impl<'de> Visitor<'de> for UserIdVisitor {
            type Value = UserId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a positive user ID encoded as a string or integer")
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                UserId::new(value).map_err(E::custom)
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let value = i64::try_from(value).map_err(E::custom)?;
                self.visit_i64(value)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let value = value.parse::<i64>().map_err(E::custom)?;
                self.visit_i64(value)
            }
        }

        deserializer.deserialize_any(UserIdVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidIdentifier> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(InvalidIdentifier::SessionId);
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidIdentifier {
    #[error("user ID must be a positive integer")]
    UserId,
    #[error("session ID must not be empty")]
    SessionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct JwtClaims {
    /// Standard JWT subject. The `id` alias supports legacy tokens.
    #[serde(alias = "id")]
    pub sub: UserId,
    pub sid: SessionId,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub aud: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedUser {
    pub id: i64,
    pub username: String,
    pub main_group: UserRole,
    pub permissions: Vec<UserRole>,
    pub avatar: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    pub user: AuthenticatedUser,
    pub session_id: SessionId,
    pub token_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: SessionId,
    pub user_id: UserId,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Session {
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims_json(subject_field: &str, subject: &str) -> String {
        format!(
            r#"{{"{subject_field}":{subject},"sid":"session-1","exp":200,"iat":100,"iss":"lara","aud":"lara-api"}}"#
        )
    }

    #[test]
    fn serializes_subject_as_standard_string_claim() {
        let claims = JwtClaims {
            sub: UserId::new(42).unwrap(),
            sid: SessionId::new("session-1").unwrap(),
            exp: 200,
            iat: 100,
            iss: "lara".into(),
            aud: "lara-api".into(),
        };

        let value = serde_json::to_value(claims).unwrap();

        assert_eq!(value["sub"], "42");
        assert!(value.get("id").is_none());
    }

    #[test]
    fn accepts_legacy_numeric_id_during_migration() {
        let claims: JwtClaims = serde_json::from_str(&claims_json("id", "42")).unwrap();

        assert_eq!(claims.sub, UserId::new(42).unwrap());
    }

    #[test]
    fn rejects_non_positive_user_id() {
        let result = serde_json::from_str::<JwtClaims>(&claims_json("sub", "0"));

        assert!(result.is_err());
    }

    #[test]
    fn session_is_active_only_before_expiration_and_before_revocation() {
        let now = DateTime::from_timestamp(1_000, 0).unwrap();
        let session = Session {
            id: SessionId::new("session-1").unwrap(),
            user_id: UserId::new(42).unwrap(),
            expires_at: DateTime::from_timestamp(1_001, 0).unwrap(),
            revoked_at: None,
        };

        assert!(session.is_active(now));

        let expired = Session {
            expires_at: now,
            ..session.clone()
        };
        assert!(!expired.is_active(now));

        let revoked = Session {
            revoked_at: Some(DateTime::from_timestamp(999, 0).unwrap()),
            ..session
        };
        assert!(!revoked.is_active(now));
    }
}
