use std::sync::Arc;

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    response::{IntoResponse, Response},
};
use thiserror::Error;

use crate::auth::{
    application::authenticate_jwt::{AuthenticateBearerToken, AuthenticationError},
    domain::models::AuthenticatedPrincipal,
};

#[derive(Debug, Error)]
pub enum JwtRejection {
    #[error("unauthorized")]
    Unauthorized,
    #[error("authentication service unavailable")]
    Unavailable,
}

impl IntoResponse for JwtRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Authentication service unavailable",
            )
                .into_response(),
        }
    }
}

impl From<AuthenticationError> for JwtRejection {
    fn from(error: AuthenticationError) -> Self {
        match error {
            AuthenticationError::Unauthorized => Self::Unauthorized,
            AuthenticationError::Unavailable => Self::Unavailable,
        }
    }
}

/// Implement this for the application's Axum state.
pub trait JwtExtractorState: Send + Sync {
    fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken>;
}

/// Authentication context whose JWT, server-side session and current user
/// workspace membership have all been validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentSession(pub AuthenticatedPrincipal);

impl<S> FromRequestParts<S> for CurrentSession
where
    S: JwtExtractorState,
{
    type Rejection = JwtRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(JwtRejection::Unauthorized)?;

        let (scheme, token) = auth_header
            .split_once(' ')
            .ok_or(JwtRejection::Unauthorized)?;

        if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() || token.contains(' ') {
            return Err(JwtRejection::Unauthorized);
        }

        let principal = state.jwt_authenticator().authenticate(token).await?;

        Ok(CurrentSession(principal))
    }
}

#[cfg(test)]
mod tests {
    use std::{future, future::Future, pin::Pin};

    use axum::{extract::FromRequestParts, http::Request};

    use chrono::{Duration, Utc};

    use crate::auth::domain::models::{AuthenticatedUser, SessionId};
    use crate::shared::user_role::UserRole;

    use super::*;

    struct Authenticator(Result<AuthenticatedPrincipal, AuthenticationError>);

    impl AuthenticateBearerToken for Authenticator {
        fn authenticate<'a>(
            &'a self,
            _token: &'a str,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<AuthenticatedPrincipal, AuthenticationError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(future::ready(self.0.clone()))
        }
    }

    struct TestState(Arc<dyn AuthenticateBearerToken>);

    impl JwtExtractorState for TestState {
        fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
            Arc::clone(&self.0)
        }
    }

    fn principal() -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            user: AuthenticatedUser {
                id: 42,
                username: "neo".into(),
                main_group: UserRole::CHALLENGER,
                permissions: vec![UserRole::CHALLENGER, UserRole::ADMIN],
                avatar: None,
            },
            session_id: SessionId::new("session-1").unwrap(),
            token_expires_at: Utc::now() + Duration::minutes(5),
        }
    }

    #[tokio::test]
    async fn extracts_authenticated_session_from_bearer_token() {
        let expected = principal();
        let state = TestState(Arc::new(Authenticator(Ok(expected.clone()))));
        let request = Request::builder()
            .header(AUTHORIZATION, "Bearer signed.jwt")
            .body(())
            .unwrap();
        let (mut parts, _) = request.into_parts();

        let current = CurrentSession::from_request_parts(&mut parts, &state)
            .await
            .unwrap();

        assert_eq!(current.0, expected);
    }

    #[tokio::test]
    async fn rejects_missing_or_malformed_authorization_header() {
        let state = TestState(Arc::new(Authenticator(Ok(principal()))));

        for header in [
            None,
            Some("Basic token"),
            Some("Bearer"),
            Some("Bearer a b"),
        ] {
            let mut builder = Request::builder();
            if let Some(header) = header {
                builder = builder.header(AUTHORIZATION, header);
            }
            let (mut parts, _) = builder.body(()).unwrap().into_parts();

            let rejection = CurrentSession::from_request_parts(&mut parts, &state)
                .await
                .unwrap_err();

            assert_eq!(rejection.into_response().status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn maps_invalid_credentials_to_unauthorized() {
        let state = TestState(Arc::new(Authenticator(Err(
            AuthenticationError::Unauthorized,
        ))));
        let request = Request::builder()
            .header(AUTHORIZATION, "Bearer invalid.jwt")
            .body(())
            .unwrap();
        let (mut parts, _) = request.into_parts();

        let rejection = CurrentSession::from_request_parts(&mut parts, &state)
            .await
            .unwrap_err();

        assert_eq!(rejection.into_response().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn maps_dependency_failure_to_service_unavailable() {
        let state = TestState(Arc::new(Authenticator(Err(
            AuthenticationError::Unavailable,
        ))));
        let request = Request::builder()
            .header(AUTHORIZATION, "Bearer signed.jwt")
            .body(())
            .unwrap();
        let (mut parts, _) = request.into_parts();

        let rejection = CurrentSession::from_request_parts(&mut parts, &state)
            .await
            .unwrap_err();

        assert_eq!(
            rejection.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
