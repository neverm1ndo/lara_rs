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
    configuration::domain::{ConfigurationAccess, ConfigurationAccessError},
    shared::file_storage::path::RelativeStoragePath,
};

/// State contract required by configuration authorization. Authentication is
/// inherited from `JwtExtractorState`; this trait only contributes the
/// configured capability boundary.
pub trait ConfigurationAuthorizationState: JwtExtractorState {
    fn configurator_directory(&self) -> &RelativeStoragePath;
}

/// A validated current session paired with its configuration filesystem
/// capability. Protected handlers should require this extractor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedConfiguration {
    principal: AuthenticatedPrincipal,
    access: ConfigurationAccess,
}

impl AuthorizedConfiguration {
    pub fn principal(&self) -> &AuthenticatedPrincipal {
        &self.principal
    }

    pub fn access(&self) -> &ConfigurationAccess {
        &self.access
    }

    pub fn into_parts(self) -> (AuthenticatedPrincipal, ConfigurationAccess) {
        (self.principal, self.access)
    }
}

impl<S> FromRequestParts<S> for AuthorizedConfiguration
where
    S: ConfigurationAuthorizationState,
{
    type Rejection = ConfigurationAuthorizationRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let CurrentSession(principal) = CurrentSession::from_request_parts(parts, state).await?;
        let access = ConfigurationAccess::authorize(
            principal.user.main_group,
            &principal.user.permissions,
            state.configurator_directory(),
        )?;

        Ok(Self { principal, access })
    }
}

#[derive(Debug, Error)]
pub enum ConfigurationAuthorizationRejection {
    #[error(transparent)]
    Authentication(#[from] JwtRejection),
    #[error("forbidden")]
    Forbidden,
}

impl From<ConfigurationAccessError> for ConfigurationAuthorizationRejection {
    fn from(_: ConfigurationAccessError) -> Self {
        Self::Forbidden
    }
}

impl IntoResponse for ConfigurationAuthorizationRejection {
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
        configuration::domain::ConfigurationAccessLevel,
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
        configurator_directory: RelativeStoragePath,
    }

    impl JwtExtractorState for TestState {
        fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
            Arc::clone(&self.authenticator)
        }
    }

    impl ConfigurationAuthorizationState for TestState {
        fn configurator_directory(&self) -> &RelativeStoragePath {
            &self.configurator_directory
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
            configurator_directory: RelativeStoragePath::new("scriptfiles/config").unwrap(),
        }
    }

    async fn extract(
        state: &TestState,
        authorization: Option<&str>,
    ) -> Result<AuthorizedConfiguration, ConfigurationAuthorizationRejection> {
        let mut builder = Request::builder();
        if let Some(value) = authorization {
            builder = builder.header(AUTHORIZATION, value);
        }
        let (mut parts, _) = builder.body(()).unwrap().into_parts();
        AuthorizedConfiguration::from_request_parts(&mut parts, state).await
    }

    #[tokio::test]
    async fn authorizes_developer_with_the_server_root_capability() {
        let expected = principal(UserRole::Developer, vec![]);
        let authorized = extract(&state(Ok(expected.clone())), Some("Bearer signed.jwt"))
            .await
            .unwrap();

        assert_eq!(authorized.principal(), &expected);
        assert_eq!(
            authorized.access().level(),
            ConfigurationAccessLevel::Developer
        );
        assert!(authorized.access().storage_root().is_root());
    }

    #[tokio::test]
    async fn authorizes_configurator_permission_with_the_narrow_capability() {
        let authenticated = principal(UserRole::Challenger, vec![UserRole::Configurator]);
        let authorized = extract(&state(Ok(authenticated)), Some("Bearer signed.jwt"))
            .await
            .unwrap();

        assert_eq!(
            authorized.access().level(),
            ConfigurationAccessLevel::Configurator
        );
        assert_eq!(
            authorized.access().storage_root(),
            &RelativeStoragePath::new("scriptfiles/config").unwrap()
        );
    }

    #[tokio::test]
    async fn rejects_an_authenticated_user_without_an_allowed_role() {
        let authenticated = principal(UserRole::Admin, vec![UserRole::Backuper]);
        let rejection = extract(&state(Ok(authenticated)), Some("Bearer signed.jwt"))
            .await
            .unwrap_err();

        assert_eq!(rejection.into_response().status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn preserves_authentication_status_codes() {
        let authenticated = principal(UserRole::Developer, vec![]);
        let missing = extract(&state(Ok(authenticated)), None).await.unwrap_err();
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
