use std::error::Error;

use crate::auth::domain::models::JwtClaims;

/// Signs claims prepared by the authentication application service.
pub trait JwtIssuer: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn issue(&self, claims: &JwtClaims) -> Result<String, Self::Error>;
}
