use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use thiserror::Error;

use crate::{
    auth::{
        domain::models::AuthenticatedPrincipal,
        presentation::extractors::{CurrentSession, JwtExtractorState, JwtRejection},
    },
    maps::domain::{MapAccess, MapAccessError},
};

/// State contract for maps authorization. Maps has no role-dependent scope,
/// so JWT authentication is the only state dependency.
pub trait MapsAuthorizationState: JwtExtractorState {}

impl<T> MapsAuthorizationState for T where T: JwtExtractorState {}

/// A current authenticated session paired with the maps-domain authorization
/// decision. Every maps handler must require this extractor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedMaps {
    principal: AuthenticatedPrincipal,
    access: MapAccess,
}

impl AuthorizedMaps {
    pub fn principal(&self) -> &AuthenticatedPrincipal {
        &self.principal
    }

    pub fn access(&self) -> MapAccess {
        self.access
    }

    pub fn into_parts(self) -> (AuthenticatedPrincipal, MapAccess) {
        (self.principal, self.access)
    }
}

impl<S> FromRequestParts<S> for AuthorizedMaps
where
    S: MapsAuthorizationState,
{
    type Rejection = MapsAuthorizationRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let CurrentSession(principal) = CurrentSession::from_request_parts(parts, state).await?;
        let access = MapAccess::authorize(
            principal.user.main_group,
            principal.user.permissions.as_slice(),
        )?;

        Ok(Self { principal, access })
    }
}

#[derive(Debug, Error)]
pub enum MapsAuthorizationRejection {
    #[error(transparent)]
    Authentication(#[from] JwtRejection),
    #[error("forbidden")]
    Forbidden,
}

impl From<MapAccessError> for MapsAuthorizationRejection {
    fn from(_: MapAccessError) -> Self {
        Self::Forbidden
    }
}

impl IntoResponse for MapsAuthorizationRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Authentication(rejection) => rejection.into_response(),
            Self::Forbidden => (StatusCode::FORBIDDEN, "Forbidden").into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{future, future::Future, pin::Pin, sync::Arc};

    use axum::{
        extract::FromRequestParts,
        http::{Request, header::AUTHORIZATION},
    };
    use chrono::{Duration, Utc};

    use super::*;
    use crate::{
        auth::{
            application::authenticate_jwt::{AuthenticateBearerToken, AuthenticationError},
            domain::models::{AuthenticatedUser, SessionId},
        },
        maps::domain::MapAccessLevel,
        shared::user_role::UserRole,
    };

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

    struct TestState {
        authenticator: Arc<dyn AuthenticateBearerToken>,
    }

    impl JwtExtractorState for TestState {
        fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
            Arc::clone(&self.authenticator)
        }
    }

    fn principal(main_group: UserRole, permissions: Vec<UserRole>) -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            user: AuthenticatedUser {
                id: 42,
                username: "neo".into(),
                main_group,
                permissions,
                avatar: None,
            },
            session_id: SessionId::new("session-1").unwrap(),
            token_expires_at: Utc::now() + Duration::minutes(5),
        }
    }

    fn state(result: Result<AuthenticatedPrincipal, AuthenticationError>) -> TestState {
        TestState {
            authenticator: Arc::new(Authenticator(result)),
        }
    }

    async fn extract(
        state: &TestState,
        authorization: Option<&str>,
    ) -> Result<AuthorizedMaps, MapsAuthorizationRejection> {
        let mut builder = Request::builder();
        if let Some(value) = authorization {
            builder = builder.header(AUTHORIZATION, value);
        }
        let (mut parts, _) = builder.body(()).unwrap().into_parts();
        AuthorizedMaps::from_request_parts(&mut parts, state).await
    }

    #[tokio::test]
    async fn authorizes_developer_and_mapper_with_the_same_extractor() {
        for (role, expected) in [
            (UserRole::Developer, MapAccessLevel::Developer),
            (UserRole::Mapper, MapAccessLevel::Mapper),
        ] {
            let expected_principal = principal(role, vec![]);
            let authorized = extract(
                &state(Ok(expected_principal.clone())),
                Some("Bearer signed.jwt"),
            )
            .await
            .unwrap();

            assert_eq!(authorized.principal(), &expected_principal);
            assert_eq!(authorized.access().level(), expected);
        }
    }

    #[tokio::test]
    async fn accepts_required_role_from_permissions() {
        let expected_principal = principal(UserRole::Challenger, vec![UserRole::Mapper]);
        let authorized = extract(
            &state(Ok(expected_principal.clone())),
            Some("Bearer signed.jwt"),
        )
        .await
        .unwrap();

        let (actual_principal, access) = authorized.into_parts();
        assert_eq!(actual_principal, expected_principal);
        assert_eq!(access.level(), MapAccessLevel::Mapper);
    }

    #[tokio::test]
    async fn rejects_an_authenticated_user_without_an_allowed_role() {
        let authenticated = principal(UserRole::Admin, vec![UserRole::Configurator]);
        let rejection = extract(&state(Ok(authenticated)), Some("Bearer signed.jwt"))
            .await
            .unwrap_err();

        assert_eq!(rejection.into_response().status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn preserves_authentication_status_codes() {
        let missing = extract(&state(Ok(principal(UserRole::Mapper, vec![]))), None)
            .await
            .unwrap_err();
        assert_eq!(missing.into_response().status(), StatusCode::UNAUTHORIZED);

        let unavailable = extract(
            &state(Err(AuthenticationError::Unavailable)),
            Some("Bearer signed.jwt"),
        )
        .await
        .unwrap_err();
        assert_eq!(
            unavailable.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
