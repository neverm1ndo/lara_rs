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
        application::{
            registry::InstanceRegistry,
            runtime_state::{RuntimeStateReader, RuntimeStateRepositoryError},
        },
        domain::{
            InstanceCapabilities, InstanceCapability, InstanceEnvironment, InstanceKind,
            InstanceObservability, InstanceReadiness, InstanceRuntimeState, ProcessState,
            ReadinessStatus, ServerInstance, ServerInstanceId, TerminationEvidence,
            TerminationKind,
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

struct EmptyStates;

impl RuntimeStateReader for EmptyStates {
    fn get(
        &self,
        _instance_id: &ServerInstanceId,
    ) -> Result<
        Option<crate::server_instances::domain::InstanceRuntimeState>,
        RuntimeStateRepositoryError,
    > {
        Ok(None)
    }
}

struct FixedStates(InstanceRuntimeState);

impl RuntimeStateReader for FixedStates {
    fn get(
        &self,
        instance_id: &ServerInstanceId,
    ) -> Result<Option<InstanceRuntimeState>, RuntimeStateRepositoryError> {
        Ok((self.0.instance_id() == instance_id).then(|| self.0.clone()))
    }
}

#[derive(Clone)]
struct TestState {
    authenticator: Arc<dyn AuthenticateBearerToken>,
    registry: Arc<dyn InstanceRegistry>,
    states: Arc<dyn RuntimeStateReader>,
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

    fn runtime_state_reader(&self) -> Arc<dyn RuntimeStateReader> {
        Arc::clone(&self.states)
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
    app_with_states(principal, Arc::new(EmptyStates))
}

fn app_with_states(
    principal: Result<AuthenticatedPrincipal, AuthenticationError>,
    states: Arc<dyn RuntimeStateReader>,
) -> Router {
    Router::new()
        .merge(router::<TestState>())
        .with_state(TestState {
            authenticator: Arc::new(Authenticator(principal)),
            registry: registry(),
            states,
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

fn state_request(instance_id: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("/server-instances/{instance_id}/state"))
        .header(header::AUTHORIZATION, "Bearer signed.jwt")
        .body(Body::empty())
        .unwrap()
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

#[tokio::test]
async fn runtime_state_is_explicitly_not_observed_before_the_adapter_reports() {
    let response = app(Ok(principal(
        UserRole::Developer,
        vec![UserRole::Developer],
    )))
    .oneshot(state_request("main"))
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body = json_body(response).await;
    assert_eq!(body["schemaVersion"], 1);
    assert_eq!(body["instanceId"], "main");
    assert_eq!(body["process"]["state"], "unknown");
    assert_eq!(body["process"]["mainPid"], Value::Null);
    assert_eq!(body["readiness"]["mode"], "uds");
    assert_eq!(body["readiness"]["status"], "unknown");
    assert_eq!(body["observation"]["status"], "not_observed");
    assert_eq!(body["observation"]["observedAt"], Value::Null);
}

#[tokio::test]
async fn runtime_state_exposes_normalized_process_evidence() {
    let observed_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let snapshot = InstanceRuntimeState::observed(
        ServerInstanceId::new("main").unwrap(),
        ProcessState::Failed,
        ReadinessStatus::NotReady,
        observed_at,
        None,
        4,
        Some("invocation-42".into()),
        Some(TerminationEvidence::new(TerminationKind::ExitCode, Some(1))),
    );
    let response = app_with_states(
        Ok(principal(UserRole::Developer, vec![UserRole::Developer])),
        Arc::new(FixedStates(snapshot)),
    )
    .oneshot(state_request("main"))
    .await
    .unwrap();
    let body = json_body(response).await;

    assert_eq!(body["process"]["state"], "failed");
    assert_eq!(body["process"]["restartCount"], 4);
    assert_eq!(body["process"]["invocationId"], "invocation-42");
    assert_eq!(body["process"]["lastTermination"]["kind"], "exit_code");
    assert_eq!(body["process"]["lastTermination"]["status"], 1);
    assert_eq!(body["observation"]["status"], "observed");
    assert_eq!(body["observation"]["observedAt"], observed_at.to_rfc3339());
}

#[tokio::test]
async fn runtime_state_rejects_non_developers_and_invalid_or_unknown_instances() {
    let forbidden = app(Ok(principal(UserRole::Admin, vec![UserRole::Admin])))
        .oneshot(state_request("main"))
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json_body(forbidden).await["code"],
        "DEVELOPER_ROLE_REQUIRED"
    );

    let developer = || {
        app(Ok(principal(
            UserRole::Developer,
            vec![UserRole::Developer],
        )))
    };
    let malformed = developer()
        .oneshot(state_request("Not_Valid"))
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(malformed).await["code"], "INVALID_INSTANCE_ID");

    let missing = developer().oneshot(state_request("missing")).await.unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(missing).await["code"], "INSTANCE_NOT_FOUND");
}
