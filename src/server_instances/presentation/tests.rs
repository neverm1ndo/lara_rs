use std::{future, future::Future, pin::Pin, sync::Arc};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use chrono::{Duration, Utc};
use serde_json::Value;
use tower::ServiceExt;

use crate::{
    auth::{
        application::authenticate_jwt::{AuthenticateBearerToken, AuthenticationError},
        domain::models::{AuthenticatedPrincipal, AuthenticatedUser, SessionId},
        presentation::extractors::JwtExtractorState,
    },
    server_instances::{
        application::registry::InstanceRegistry,
        domain::{
            InstanceCapabilities, InstanceCapability, InstanceEnvironment, InstanceKind,
            InstanceObservability, InstanceReadiness, ServerInstance, ServerInstanceId,
        },
        presentation::{router, state::ServerInstancesState},
    },
    shared::user_role::UserRole,
};

struct Authenticator(Result<AuthenticatedPrincipal, AuthenticationError>);

impl AuthenticateBearerToken for Authenticator {
    fn authenticate<'a>(
        &'a self,
        _token: &'a str,
    ) -> Pin<
        Box<dyn Future<Output = Result<AuthenticatedPrincipal, AuthenticationError>> + Send + 'a>,
    > {
        Box::pin(future::ready(self.0.clone()))
    }
}

struct MemoryRegistry(Vec<ServerInstance>);

impl InstanceRegistry for MemoryRegistry {
    fn primary(&self) -> ServerInstance {
        self.0[0].clone()
    }

    fn get(&self, id: &ServerInstanceId) -> Option<ServerInstance> {
        self.0.iter().find(|instance| instance.id() == id).cloned()
    }

    fn list(&self) -> Vec<ServerInstance> {
        self.0.clone()
    }
}

#[derive(Clone)]
struct TestState {
    authenticator: Arc<dyn AuthenticateBearerToken>,
    registry: Arc<dyn InstanceRegistry>,
}

impl JwtExtractorState for TestState {
    fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
        Arc::clone(&self.authenticator)
    }
}

impl ServerInstancesState for TestState {
    fn instance_registry(&self) -> Arc<dyn InstanceRegistry> {
        Arc::clone(&self.registry)
    }
}

fn principal(main_group: UserRole, permissions: Vec<UserRole>) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        user: AuthenticatedUser {
            id: 7,
            username: "requester".into(),
            main_group,
            permissions,
            avatar: None,
        },
        session_id: SessionId::new("session-1").unwrap(),
        token_expires_at: Utc::now() + Duration::minutes(5),
    }
}

fn registry() -> Arc<dyn InstanceRegistry> {
    let primary = ServerInstance::new(
        ServerInstanceId::new("main").unwrap(),
        "Main server",
        InstanceKind::Primary,
        InstanceEnvironment::Production,
        10,
        InstanceCapabilities::primary(),
        InstanceObservability::new(InstanceReadiness::Uds, true),
    )
    .unwrap();
    let auxiliary = ServerInstance::new(
        ServerInstanceId::new("dev-dm").unwrap(),
        "Developer DM",
        InstanceKind::Auxiliary,
        InstanceEnvironment::Development,
        20,
        InstanceCapabilities::new([
            InstanceCapability::Overview,
            InstanceCapability::Lifecycle,
            InstanceCapability::Configuration,
            InstanceCapability::Incidents,
        ]),
        InstanceObservability::new(InstanceReadiness::Process, true),
    )
    .unwrap();

    Arc::new(MemoryRegistry(vec![primary, auxiliary]))
}

fn app(principal: Result<AuthenticatedPrincipal, AuthenticationError>) -> Router {
    Router::new()
        .merge(router::<TestState>())
        .with_state(TestState {
            authenticator: Arc::new(Authenticator(principal)),
            registry: registry(),
        })
}

fn request(if_none_match: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .uri("/server-instances")
        .header(header::AUTHORIZATION, "Bearer signed.jwt");
    if let Some(etag) = if_none_match {
        request = request.header(header::IF_NONE_MATCH, etag);
    }
    request.body(Body::empty()).unwrap()
}

async fn json_body(response: Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn developer_receives_all_instances_without_internal_runtime_configuration() {
    let response = app(Ok(principal(
        UserRole::Admin,
        vec![UserRole::Admin, UserRole::Developer],
    )))
    .oneshot(request(None))
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CACHE_CONTROL],
        "private, no-cache"
    );
    let etag = response.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_owned();
    let body = json_body(response).await;
    assert_eq!(body["schemaVersion"], 1);
    assert_eq!(body["revision"], etag);
    assert_eq!(body["defaultInstanceId"], "main");
    assert_eq!(body["instances"].as_array().unwrap().len(), 2);
    assert_eq!(
        body["instances"][1]["observability"]["readiness"],
        "process"
    );
    assert_eq!(
        body["instances"][1]["features"]["lara.lifecycle.v1"]["permissions"],
        serde_json::json!(["read"])
    );
    for forbidden in ["systemdUnit", "storageRoot", "udsPath"] {
        assert!(!body.to_string().contains(forbidden), "exposed {forbidden}");
    }
}

#[tokio::test]
async fn non_developer_never_receives_auxiliary_instances() {
    for role in [
        UserRole::Challenger,
        UserRole::Admin,
        UserRole::Mapper,
        UserRole::Configurator,
        UserRole::Backuper,
    ] {
        let response = app(Ok(principal(role, vec![role])))
            .oneshot(request(None))
            .await
            .unwrap();
        let body = json_body(response).await;

        assert_eq!(body["instances"].as_array().unwrap().len(), 1, "{role:?}");
        assert_eq!(body["instances"][0]["id"], "main", "{role:?}");
    }
}

#[tokio::test]
async fn matching_etag_returns_not_modified_without_a_body() {
    let app = app(Ok(principal(
        UserRole::Developer,
        vec![UserRole::Developer],
    )));
    let first = app.clone().oneshot(request(None)).await.unwrap();
    let etag = first.headers()[header::ETAG].to_str().unwrap().to_owned();

    let second = app.oneshot(request(Some(&etag))).await.unwrap();

    assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(second.headers()[header::ETAG], etag);
    assert!(
        to_bytes(second.into_body(), usize::MAX)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn endpoint_requires_authentication() {
    let response = app(Err(AuthenticationError::Unauthorized))
        .oneshot(request(None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
