use std::{
    collections::BTreeMap,
    future::{self, Future},
    path::PathBuf,
    sync::Arc,
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::AUTHORIZATION},
};
use chrono::{Duration, Utc};
use encoding_rs::UTF_8;
use tower::ServiceExt;

use crate::{
    auth::{
        application::authenticate_jwt::{AuthenticateBearerToken, AuthenticationError},
        domain::models::{AuthenticatedPrincipal, AuthenticatedUser, SessionId},
        presentation::extractors::JwtExtractorState,
    },
    configuration::{
        application::{
            artifact_service::ConfigurationArtifactService,
            instance_text::InstanceConfigurationTextService,
            mutation_log::{
                ConfigurationMutationLog, ConfigurationMutationLogError,
                ConfigurationMutationRecord, ConfigurationMutationState, MutationLogFuture,
            },
            mutation_service::ConfigurationMutationService,
            target::{
                ConfigurationAccessScope, ConfigurationTarget, ConfigurationTargetError,
                ConfigurationTargetResolver,
            },
        },
        domain::ConfigurationFilePolicy,
        infrastructure::{
            artifact_service::LocalConfigurationArtifactService,
            instance_text::LocalInstanceConfigurationTextService,
        },
        presentation::{instance_routes, instance_state::InstanceConfigurationState},
    },
    shared::{
        file_storage::{
            guard::NoBackupProvider,
            local::{FileStorageLimits, LocalFileStorage},
            path::RelativeStoragePath,
        },
        user_role::UserRole,
    },
};

struct Authenticator(AuthenticatedPrincipal);

impl AuthenticateBearerToken for Authenticator {
    fn authenticate<'a>(
        &'a self,
        _: &'a str,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<AuthenticatedPrincipal, AuthenticationError>> + Send + 'a>,
    > {
        Box::pin(future::ready(Ok(self.0.clone())))
    }
}

struct Resolver(BTreeMap<String, Arc<ConfigurationTarget>>);

struct UnavailableMutationLog;

impl ConfigurationMutationLog for UnavailableMutationLog {
    fn reserve<'a>(&'a self, _: &'a ConfigurationMutationRecord) -> MutationLogFuture<'a, ()> {
        Box::pin(async {
            Err(ConfigurationMutationLogError::Unavailable(
                "test log".into(),
            ))
        })
    }
    fn by_key<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> MutationLogFuture<'a, Option<ConfigurationMutationRecord>> {
        Box::pin(async {
            Err(ConfigurationMutationLogError::Unavailable(
                "test log".into(),
            ))
        })
    }
    fn by_id<'a>(
        &'a self,
        _: &'a str,
    ) -> MutationLogFuture<'a, Option<ConfigurationMutationRecord>> {
        Box::pin(async {
            Err(ConfigurationMutationLogError::Unavailable(
                "test log".into(),
            ))
        })
    }
    fn transition<'a>(
        &'a self,
        _: &'a str,
        _: ConfigurationMutationState,
        _: ConfigurationMutationRecord,
    ) -> MutationLogFuture<'a, bool> {
        Box::pin(async {
            Err(ConfigurationMutationLogError::Unavailable(
                "test log".into(),
            ))
        })
    }
    fn unresolved<'a>(&'a self) -> MutationLogFuture<'a, Vec<ConfigurationMutationRecord>> {
        Box::pin(async {
            Err(ConfigurationMutationLogError::Unavailable(
                "test log".into(),
            ))
        })
    }
    fn claim_event<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
    ) -> MutationLogFuture<'a, Option<ConfigurationMutationRecord>> {
        Box::pin(async {
            Err(ConfigurationMutationLogError::Unavailable(
                "test log".into(),
            ))
        })
    }
    fn acknowledge_event<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
    ) -> MutationLogFuture<'a, ()> {
        Box::pin(async {
            Err(ConfigurationMutationLogError::Unavailable(
                "test log".into(),
            ))
        })
    }
}

impl ConfigurationTargetResolver for Resolver {
    fn resolve(&self, id: &str) -> Result<Arc<ConfigurationTarget>, ConfigurationTargetError> {
        self.0
            .get(id)
            .cloned()
            .ok_or(ConfigurationTargetError::NotFound)
    }
}

#[derive(Clone)]
struct TestState {
    authenticator: Arc<dyn AuthenticateBearerToken>,
    resolver: Arc<dyn ConfigurationTargetResolver>,
    text: Arc<dyn InstanceConfigurationTextService>,
    artifacts: Arc<dyn ConfigurationArtifactService>,
    mutation: Arc<ConfigurationMutationService>,
}

impl JwtExtractorState for TestState {
    fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
        self.authenticator.clone()
    }
}

impl InstanceConfigurationState for TestState {
    fn configuration_target_resolver(&self) -> Arc<dyn ConfigurationTargetResolver> {
        self.resolver.clone()
    }

    fn instance_text_service(&self) -> Arc<dyn InstanceConfigurationTextService> {
        self.text.clone()
    }

    fn artifact_service(&self) -> Arc<dyn ConfigurationArtifactService> {
        self.artifacts.clone()
    }

    fn configuration_mutation_service(&self) -> Arc<ConfigurationMutationService> {
        self.mutation.clone()
    }
}

struct TestRoots(PathBuf);

impl TestRoots {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("lara-configuration-http-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("primary/scriptfiles/config")).unwrap();
        std::fs::create_dir(root.join("auxiliary")).unwrap();
        std::fs::write(
            root.join("primary/scriptfiles/config/allowed.cfg"),
            b"allowed",
        )
        .unwrap();
        std::fs::write(root.join("primary/private.cfg"), b"private").unwrap();
        std::fs::write(root.join("auxiliary/server.cfg"), b"auxiliary").unwrap();
        Self(root)
    }

    async fn resolver(&self) -> Arc<dyn ConfigurationTargetResolver> {
        let mut targets = BTreeMap::new();
        for (id, scope) in [
            (
                "primary",
                ConfigurationAccessScope::Primary {
                    configurator_directory: RelativeStoragePath::new("scriptfiles/config").unwrap(),
                },
            ),
            ("auxiliary", ConfigurationAccessScope::Auxiliary),
        ] {
            let storage = LocalFileStorage::open(
                self.0.join(id),
                FileStorageLimits::new(8, 100, 1024).unwrap(),
            )
            .await
            .unwrap();
            targets.insert(
                id.to_owned(),
                Arc::new(ConfigurationTarget::new(
                    id.to_owned(),
                    storage,
                    ConfigurationFilePolicy::new([], [], []).unwrap(),
                    UTF_8,
                    vec![],
                    scope,
                )),
            );
        }
        Arc::new(Resolver(targets))
    }
}

impl Drop for TestRoots {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn principal(role: UserRole) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        user: AuthenticatedUser {
            id: 42,
            username: "pilot".into(),
            main_group: role,
            permissions: vec![],
            avatar: None,
        },
        session_id: SessionId::new("session-1").unwrap(),
        token_expires_at: Utc::now() + Duration::minutes(5),
    }
}

fn app(role: UserRole, resolver: Arc<dyn ConfigurationTargetResolver>) -> axum::Router {
    let text: Arc<dyn InstanceConfigurationTextService> = Arc::new(
        LocalInstanceConfigurationTextService::new(Arc::new(NoBackupProvider)),
    );
    let artifacts: Arc<dyn ConfigurationArtifactService> = Arc::new(
        LocalConfigurationArtifactService::new(Arc::new(NoBackupProvider)),
    );
    let state = TestState {
        authenticator: Arc::new(Authenticator(principal(role))),
        resolver,
        mutation: Arc::new(ConfigurationMutationService::new(
            Arc::new(UnavailableMutationLog),
            text.clone(),
            artifacts.clone(),
        )),
        text,
        artifacts,
    };
    instance_routes::router::<TestState>()
        .with_state(state)
        .split_for_parts()
        .0
}

async fn get(app: axum::Router, uri: &str) -> (StatusCode, Vec<u8>) {
    let response = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(AUTHORIZATION, "Bearer signed.jwt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    (status, body)
}

#[tokio::test]
async fn mounted_routes_enforce_instance_and_role_boundaries() {
    let roots = TestRoots::new();
    let resolver = roots.resolver().await;
    let auxiliary = "/server-instances/auxiliary/configuration/files?path=server.cfg";
    let primary = "/server-instances/primary/configuration/files?path=allowed.cfg";

    let (status, body) = get(app(UserRole::Developer, resolver.clone()), auxiliary).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"auxiliary");
    let (status, body) = get(app(UserRole::Configurator, resolver.clone()), primary).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"allowed");
    let (status, _) = get(app(UserRole::Configurator, resolver.clone()), auxiliary).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = get(
        app(UserRole::Configurator, resolver.clone()),
        "/server-instances/primary/configuration/files?path=private.cfg",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    for role in [
        UserRole::Admin,
        UserRole::Challenger,
        UserRole::Mapper,
        UserRole::Backuper,
    ] {
        let (status, _) = get(app(role, resolver.clone()), auxiliary).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{role:?}");
    }
    let (status, _) = get(
        app(UserRole::Developer, resolver.clone()),
        "/server-instances/auxiliary/configuration/files?path=../primary/private.cfg",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = get(
        app(UserRole::Developer, resolver),
        "/server-instances/auxiliary/configuration/files?path=%2Fetc%2Fpasswd",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
