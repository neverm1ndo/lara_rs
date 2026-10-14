use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode, get_current_timestamp,
};
use thiserror::Error;

use crate::auth::{
    application::{authenticate_jwt::JwtVerifier, jwt_issuer::JwtIssuer},
    domain::models::JwtClaims,
};

const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 10;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("JWT secret must not be empty")]
    EmptySecret,
    #[error("JWT issuer must not be empty")]
    EmptyIssuer,
    #[error("JWT audience must not be empty")]
    EmptyAudience,
    #[error("invalid JWT")]
    InvalidToken(#[from] jsonwebtoken::errors::Error),
    #[error("invalid JWT claims")]
    InvalidClaims,
}

#[derive(Debug, Error)]
pub enum JwtIssuanceError {
    #[error("JWT secret must not be empty")]
    EmptySecret,
    #[error("JWT issuer must not be empty")]
    EmptyIssuer,
    #[error("JWT audience must not be empty")]
    EmptyAudience,
    #[error("claims do not match JWT issuer configuration")]
    InvalidClaims,
    #[error("JWT signing failed")]
    Signing(#[from] jsonwebtoken::errors::Error),
}

pub struct Hs256JwtIssuer {
    key: EncodingKey,
    issuer: String,
    audience: String,
}

impl Hs256JwtIssuer {
    pub fn new(
        secret: impl AsRef<[u8]>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self, JwtIssuanceError> {
        let secret = secret.as_ref();
        if secret.is_empty() {
            return Err(JwtIssuanceError::EmptySecret);
        }

        let issuer = issuer.into();
        if issuer.trim().is_empty() {
            return Err(JwtIssuanceError::EmptyIssuer);
        }

        let audience = audience.into();
        if audience.trim().is_empty() {
            return Err(JwtIssuanceError::EmptyAudience);
        }

        Ok(Self {
            key: EncodingKey::from_secret(secret),
            issuer,
            audience,
        })
    }
}

impl JwtIssuer for Hs256JwtIssuer {
    type Error = JwtIssuanceError;

    fn issue(&self, claims: &JwtClaims) -> Result<String, Self::Error> {
        let now = get_current_timestamp() as i64;
        if claims.iss != self.issuer
            || claims.aud != self.audience
            || claims.iat <= 0
            || claims.iat > now.saturating_add(DEFAULT_CLOCK_SKEW_SECONDS as i64)
            || claims.exp <= claims.iat
            || claims.exp <= now
        {
            return Err(JwtIssuanceError::InvalidClaims);
        }

        Ok(encode(&Header::new(Algorithm::HS256), claims, &self.key)?)
    }
}

pub struct Hs256JwtVerifier {
    key: DecodingKey,
    validation: Validation,
}

impl Hs256JwtVerifier {
    pub fn new(
        secret: impl AsRef<[u8]>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self, JwtError> {
        Self::with_clock_skew(secret, issuer, audience, DEFAULT_CLOCK_SKEW_SECONDS)
    }

    pub fn with_clock_skew(
        secret: impl AsRef<[u8]>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        clock_skew_seconds: u64,
    ) -> Result<Self, JwtError> {
        let secret = secret.as_ref();
        if secret.is_empty() {
            return Err(JwtError::EmptySecret);
        }

        let issuer = issuer.into();
        if issuer.trim().is_empty() {
            return Err(JwtError::EmptyIssuer);
        }

        let audience = audience.into();
        if audience.trim().is_empty() {
            return Err(JwtError::EmptyAudience);
        }

        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = clock_skew_seconds;
        validation.set_required_spec_claims(&["sub", "exp", "iss", "aud"]);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);

        Ok(Self {
            key: DecodingKey::from_secret(secret),
            validation,
        })
    }
}

impl JwtVerifier for Hs256JwtVerifier {
    type Error = JwtError;

    fn verify(&self, token: &str) -> Result<JwtClaims, Self::Error> {
        let claims = decode::<JwtClaims>(token, &self.key, &self.validation)?.claims;
        let now = get_current_timestamp() as i64;
        let clock_skew = i64::try_from(self.validation.leeway).unwrap_or(i64::MAX);

        // `jsonwebtoken` validates `exp`; these checks cover mandatory `iat`
        // semantics and reject internally inconsistent token lifetimes.
        if claims.iat <= 0
            || claims.iat > now.saturating_add(clock_skew)
            || claims.exp <= claims.iat
        {
            return Err(JwtError::InvalidClaims);
        }

        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{EncodingKey, Header, decode_header, encode};
    use serde::Serialize;
    use serde_json::json;

    use crate::auth::domain::models::{SessionId, UserId};

    use super::*;

    const ISSUER: &str = "lara";
    const AUDIENCE: &str = "lara-api";

    fn claims(expires_at: u64) -> JwtClaims {
        JwtClaims {
            sub: UserId::new(42).unwrap(),
            sid: SessionId::new("session-1").unwrap(),
            exp: expires_at as i64,
            iat: get_current_timestamp() as i64,
            iss: ISSUER.into(),
            aud: AUDIENCE.into(),
        }
    }

    fn token<T: Serialize>(algorithm: Algorithm, secret: &[u8], claims: &T) -> String {
        encode(
            &Header::new(algorithm),
            claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    #[test]
    fn accepts_only_valid_non_expired_hs256_tokens() {
        let verifier = Hs256JwtVerifier::new("secret", ISSUER, AUDIENCE).unwrap();
        let valid = token(
            Algorithm::HS256,
            b"secret",
            &claims(get_current_timestamp() + 60),
        );
        assert_eq!(verifier.verify(&valid).unwrap().sub.get(), 42);

        let wrong_secret = token(
            Algorithm::HS256,
            b"wrong",
            &claims(get_current_timestamp() + 60),
        );
        assert!(verifier.verify(&wrong_secret).is_err());

        let expired = token(
            Algorithm::HS256,
            b"secret",
            &claims(get_current_timestamp() - DEFAULT_CLOCK_SKEW_SECONDS - 1),
        );
        assert!(verifier.verify(&expired).is_err());

        let wrong_algorithm = token(
            Algorithm::HS384,
            b"secret",
            &claims(get_current_timestamp() + 60),
        );
        assert!(verifier.verify(&wrong_algorithm).is_err());
    }

    #[test]
    fn issues_hs256_token_accepted_by_the_verifier() {
        let issuer = Hs256JwtIssuer::new("secret", ISSUER, AUDIENCE).unwrap();
        let verifier = Hs256JwtVerifier::new("secret", ISSUER, AUDIENCE).unwrap();
        let claims = claims(get_current_timestamp() + 60);

        let encoded = issuer.issue(&claims).unwrap();

        assert_eq!(decode_header(&encoded).unwrap().alg, Algorithm::HS256);
        assert_eq!(verifier.verify(&encoded).unwrap(), claims);
    }

    #[test]
    fn issuer_validates_configuration_and_claims() {
        assert!(matches!(
            Hs256JwtIssuer::new("", ISSUER, AUDIENCE),
            Err(JwtIssuanceError::EmptySecret)
        ));
        assert!(matches!(
            Hs256JwtIssuer::new("secret", "", AUDIENCE),
            Err(JwtIssuanceError::EmptyIssuer)
        ));
        assert!(matches!(
            Hs256JwtIssuer::new("secret", ISSUER, ""),
            Err(JwtIssuanceError::EmptyAudience)
        ));

        let issuer = Hs256JwtIssuer::new("secret", ISSUER, AUDIENCE).unwrap();
        let now = get_current_timestamp();

        let mut wrong_issuer = claims(now + 60);
        wrong_issuer.iss = "another-service".into();
        assert!(matches!(
            issuer.issue(&wrong_issuer),
            Err(JwtIssuanceError::InvalidClaims)
        ));

        let mut wrong_audience = claims(now + 60);
        wrong_audience.aud = "another-api".into();
        assert!(matches!(
            issuer.issue(&wrong_audience),
            Err(JwtIssuanceError::InvalidClaims)
        ));

        let expired = claims(now);
        assert!(matches!(
            issuer.issue(&expired),
            Err(JwtIssuanceError::InvalidClaims)
        ));

        let mut inconsistent = claims(now + 60);
        inconsistent.iat = inconsistent.exp;
        assert!(matches!(
            issuer.issue(&inconsistent),
            Err(JwtIssuanceError::InvalidClaims)
        ));
    }

    #[test]
    fn validates_startup_configuration() {
        assert!(matches!(
            Hs256JwtVerifier::new("", ISSUER, AUDIENCE),
            Err(JwtError::EmptySecret)
        ));
        assert!(matches!(
            Hs256JwtVerifier::new("secret", "", AUDIENCE),
            Err(JwtError::EmptyIssuer)
        ));
        assert!(matches!(
            Hs256JwtVerifier::new("secret", ISSUER, ""),
            Err(JwtError::EmptyAudience)
        ));
    }

    #[test]
    fn rejects_unexpected_issuer_or_audience() {
        let verifier = Hs256JwtVerifier::new("secret", ISSUER, AUDIENCE).unwrap();
        let mut wrong_issuer = claims(get_current_timestamp() + 60);
        wrong_issuer.iss = "another-service".into();
        let encoded = token(Algorithm::HS256, b"secret", &wrong_issuer);
        assert!(verifier.verify(&encoded).is_err());

        let mut wrong_audience = claims(get_current_timestamp() + 60);
        wrong_audience.aud = "another-api".into();
        let encoded = token(Algorithm::HS256, b"secret", &wrong_audience);
        assert!(verifier.verify(&encoded).is_err());
    }

    #[test]
    fn rejects_missing_or_inconsistent_time_claims() {
        let verifier = Hs256JwtVerifier::new("secret", ISSUER, AUDIENCE).unwrap();
        let now = get_current_timestamp();
        let missing_iat_and_sid = json!({
            "sub": "42",
            "exp": now + 60,
            "iss": ISSUER,
            "aud": AUDIENCE,
        });
        let encoded = token(Algorithm::HS256, b"secret", &missing_iat_and_sid);
        assert!(verifier.verify(&encoded).is_err());

        let mut future_issued = claims(now + 120);
        future_issued.iat = (now + DEFAULT_CLOCK_SKEW_SECONDS + 1) as i64;
        let encoded = token(Algorithm::HS256, b"secret", &future_issued);
        assert!(matches!(
            verifier.verify(&encoded),
            Err(JwtError::InvalidClaims)
        ));

        let mut invalid_lifetime = claims(now + 60);
        invalid_lifetime.iat = invalid_lifetime.exp;
        let encoded = token(Algorithm::HS256, b"secret", &invalid_lifetime);
        assert!(matches!(
            verifier.verify(&encoded),
            Err(JwtError::InvalidClaims)
        ));
    }

    #[test]
    fn rejects_each_missing_mandatory_claim_and_empty_session_id() {
        let verifier = Hs256JwtVerifier::new("secret", ISSUER, AUDIENCE).unwrap();
        let complete = serde_json::to_value(claims(get_current_timestamp() + 60)).unwrap();

        for claim in ["sub", "sid", "exp", "iat", "iss", "aud"] {
            let mut incomplete = complete.clone();
            incomplete.as_object_mut().unwrap().remove(claim);
            let encoded = token(Algorithm::HS256, b"secret", &incomplete);

            assert!(
                verifier.verify(&encoded).is_err(),
                "accepted missing {claim}"
            );
        }

        let mut empty_session = complete;
        empty_session["sid"] = json!("");
        let encoded = token(Algorithm::HS256, b"secret", &empty_session);
        assert!(verifier.verify(&encoded).is_err());
    }
}
