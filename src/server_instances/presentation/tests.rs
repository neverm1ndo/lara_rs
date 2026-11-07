use std::{collections::HashMap, sync::Mutex};
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
            incident_management::{
                IncidentFilters, IncidentListCursor, IncidentManagementService,
                IncidentManagementStore, ManagementFuture, ReviewReplay,
            },
            incidents::IncidentStoreError,
            lifecycle_service::LifecycleOperationService,
            registry::InstanceRegistry,
            runtime_state::{RuntimeStateReader, RuntimeStateRepositoryError},
        },
        domain::{
            Incident, IncidentConfidence, IncidentEvidence, IncidentFactId, IncidentId,
            IncidentKind, IncidentReviewState, IncidentUnitName, InstanceCapabilities,
            InstanceCapability, InstanceClassification, InstanceEnvironment, InstanceKind,
            InstanceManagement, InstanceObservability, InstanceReadiness, InstanceRuntimeState,
            ProcessState, ReadinessStatus, ServerInstance, ServerInstanceId, TerminationEvidence,
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
    incident_service: Option<Arc<IncidentManagementService>>,
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

    fn lifecycle_operation_service(&self) -> Arc<LifecycleOperationService> {
        panic!("lifecycle endpoints use their dedicated application tests")
    }
    fn incident_management_service(&self) -> Arc<IncidentManagementService> {
        self.incident_service
            .as_ref()
            .expect("incident test service")
            .clone()
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
        InstanceClassification::new(
            InstanceKind::Primary,
            InstanceEnvironment::Production,
            InstanceManagement::External,
        ),
        10,
        InstanceCapabilities::primary(),
        InstanceObservability::new(InstanceReadiness::Uds, true),
    )
    .unwrap();
    let auxiliary = ServerInstance::new(
        ServerInstanceId::new("dev-dm").unwrap(),
        "Developer DM",
        InstanceClassification::new(
            InstanceKind::Auxiliary,
            InstanceEnvironment::Development,
            InstanceManagement::Systemd,
        ),
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
            incident_service: None,
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

#[derive(Default)]
struct IncidentMemory {
    incidents: Mutex<Vec<Incident>>,
    requests: Mutex<HashMap<(String, i64, String), ReviewReplay>>,
}

impl IncidentManagementStore for IncidentMemory {
    fn list<'a>(
        &'a self,
        instance: &'a ServerInstanceId,
        filters: &'a IncidentFilters,
        cursor: Option<&'a IncidentListCursor>,
        limit: usize,
    ) -> ManagementFuture<'a, Vec<Incident>> {
        Box::pin(async move {
            let mut items: Vec<_> = self
                .incidents
                .lock()
                .unwrap()
                .iter()
                .filter(|incident| {
                    incident.instance_id() == instance
                        && filters
                            .operational_state
                            .is_none_or(|state| incident.operational_state() == state)
                        && filters
                            .review_state
                            .is_none_or(|state| incident.review_state() == state)
                        && filters
                            .opened_from
                            .is_none_or(|from| incident.opened_at() >= from)
                        && filters
                            .opened_to
                            .is_none_or(|to| incident.opened_at() <= to)
                        && cursor.is_none_or(|cursor| {
                            (
                                incident.opened_at().timestamp_millis(),
                                incident.id().to_string(),
                            ) < (cursor.opened_at_millis, cursor.incident_id.clone())
                        })
                })
                .cloned()
                .collect();
            items.sort_by(|a, b| {
                (b.opened_at().timestamp_millis(), b.id().to_string())
                    .cmp(&(a.opened_at().timestamp_millis(), a.id().to_string()))
            });
            items.truncate(limit);
            Ok(items)
        })
    }
    fn get<'a>(&'a self, id: IncidentId) -> ManagementFuture<'a, Option<Incident>> {
        Box::pin(async move {
            Ok(self
                .incidents
                .lock()
                .unwrap()
                .iter()
                .find(|item| item.id() == id)
                .cloned())
        })
    }
    fn by_review_key<'a>(
        &'a self,
        id: IncidentId,
        actor: i64,
        key: &'a str,
    ) -> ManagementFuture<'a, Option<ReviewReplay>> {
        Box::pin(async move {
            Ok(self
                .requests
                .lock()
                .unwrap()
                .get(&(id.to_string(), actor, key.to_owned()))
                .cloned())
        })
    }
    fn save_review<'a>(
        &'a self,
        incident: &'a Incident,
        expected: u64,
        actor: i64,
        key: &'a str,
        replay: &'a ReviewReplay,
    ) -> ManagementFuture<'a, ()> {
        Box::pin(async move {
            let mut all = self.incidents.lock().unwrap();
            let stored = all
                .iter_mut()
                .find(|item| item.id() == incident.id())
                .ok_or_else(|| IncidentStoreError::InvalidData("missing fixture".into()))?;
            if stored.version() != expected {
                return Err(IncidentStoreError::ConcurrentModification);
            }
            *stored = incident.clone();
            self.requests.lock().unwrap().insert(
                (incident.id().to_string(), actor, key.to_owned()),
                replay.clone(),
            );
            Ok(())
        })
    }
}

fn incident_fixture(seconds: i64) -> Incident {
    let at = chrono::DateTime::from_timestamp(1_700_000_000 + seconds, 0).unwrap();
    let evidence = IncidentEvidence::new(
        IncidentFactId::live(format!("fixture-{seconds}")).unwrap(),
        IncidentUnitName::new("lara-game@dev-dm.service").unwrap(),
        at,
        ProcessState::Failed,
        None,
        None,
        Some(TerminationEvidence::new(TerminationKind::ExitCode, Some(1))),
        IncidentConfidence::Confirmed,
    )
    .unwrap();
    Incident::open(
        IncidentId::new(),
        ServerInstanceId::new("dev-dm").unwrap(),
        IncidentKind::Outage,
        evidence,
    )
    .unwrap()
}

fn incident_app(role: UserRole, memory: Arc<IncidentMemory>) -> Router {
    incident_app_with_permissions(role, vec![role], memory)
}

fn incident_app_with_permissions(
    role: UserRole,
    permissions: Vec<UserRole>,
    memory: Arc<IncidentMemory>,
) -> Router {
    let registry = registry();
    let service = Arc::new(IncidentManagementService::new(registry.clone(), memory));
    Router::new()
        .merge(router::<TestState>())
        .with_state(TestState {
            authenticator: Arc::new(Authenticator(Ok(principal(role, permissions)))),
            registry,
            states: Arc::new(EmptyStates),
            incident_service: Some(service),
        })
}

fn incident_request(method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, "Bearer signed.jwt")
}

#[tokio::test]
async fn incident_http_hides_auxiliary_and_paginates_for_developer() {
    let memory = Arc::new(IncidentMemory::default());
    let first = incident_fixture(1);
    let second = incident_fixture(2);
    memory.incidents.lock().unwrap().extend([first, second]);
    let uri = "/server-instances/dev-dm/incidents?limit=1";
    for role in [UserRole::Admin, UserRole::Challenger] {
        let response = incident_app(role, memory.clone())
            .oneshot(incident_request("GET", uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let primary = incident_app(role, memory.clone())
            .oneshot(
                incident_request("GET", "/server-instances/main/incidents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(primary.status(), StatusCode::FORBIDDEN);
    }
    let response = incident_app(UserRole::Developer, memory.clone())
        .oneshot(incident_request("GET", uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let explicit_developer = incident_app_with_permissions(
        UserRole::Admin,
        vec![UserRole::Admin, UserRole::Developer],
        memory.clone(),
    )
    .oneshot(incident_request("GET", uri).body(Body::empty()).unwrap())
    .await
    .unwrap();
    assert_eq!(explicit_developer.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let page = json_body(response).await;
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    let cursor = page["nextCursor"].as_str().unwrap();
    let next = incident_app(UserRole::Developer, memory.clone())
        .oneshot(
            incident_request("GET", &format!("{uri}&cursor={cursor}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let next_page = json_body(next).await;
    assert_eq!(next_page["items"].as_array().unwrap().len(), 1);
    assert_ne!(
        page["items"][0]["incidentId"],
        next_page["items"][0]["incidentId"]
    );
    assert!(next_page["nextCursor"].is_null());
    let mismatched = incident_app(UserRole::Developer, memory)
        .oneshot(
            incident_request(
                "GET",
                &format!("{uri}&reviewState=unreviewed&cursor={cursor}"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mismatched.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn incident_review_requires_etag_and_replays_same_request() {
    let memory = Arc::new(IncidentMemory::default());
    let incident = incident_fixture(1);
    let uri = format!(
        "/server-instances/dev-dm/incidents/{}/review",
        incident.id()
    );
    memory.incidents.lock().unwrap().push(incident);
    let request = |key: &str, version: Option<&str>, note: &str| {
        let mut builder = incident_request("PATCH", &uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header("idempotency-key", key);
        if let Some(version) = version {
            builder = builder.header(header::IF_MATCH, version);
        }
        builder
            .body(Body::from(format!(
                r#"{{"reviewState":"acknowledged","note":"{note}"}}"#
            )))
            .unwrap()
    };
    let app = || incident_app(UserRole::Developer, memory.clone());
    assert_eq!(
        app()
            .oneshot(request("one", None, "checked"))
            .await
            .unwrap()
            .status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    let first = app()
        .oneshot(request("one", Some("\"0\""), "checked"))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.headers()[header::ETAG], "\"1\"");
    let first_body = json_body(first).await;
    let replay = app()
        .oneshot(request("one", Some("\"0\""), "checked"))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(json_body(replay).await, first_body);
    assert_eq!(
        app()
            .oneshot(request("one", Some("\"0\""), "different"))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        app()
            .oneshot(request("two", Some("\"0\""), "checked"))
            .await
            .unwrap()
            .status(),
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        memory.incidents.lock().unwrap()[0].review_state(),
        IncidentReviewState::Acknowledged
    );
    assert_eq!(
        memory.incidents.lock().unwrap()[0].review_history().len(),
        1
    );
    let hidden = incident_app(UserRole::Admin, memory)
        .oneshot(request("three", None, "checked"))
        .await
        .unwrap();
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
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
    assert_eq!(body["instances"][0]["management"], "external");
    assert_eq!(
        body["instances"][0]["observability"]["processMonitoring"],
        false
    );
    assert_eq!(body["instances"][1]["management"], "systemd");
    assert_eq!(
        body["instances"][1]["observability"]["processMonitoring"],
        true
    );
    assert_eq!(
        body["instances"][1]["observability"]["readiness"],
        "process"
    );
    assert_eq!(
        body["instances"][1]["features"]["lara.lifecycle.v1"]["permissions"],
        serde_json::json!(["read", "start", "stop", "restart"])
    );
    assert_eq!(
        body["instances"][1]["features"]["lara.incidents.v1"]["permissions"],
        serde_json::json!(["read", "acknowledge"])
    );
    assert_eq!(
        body["instances"][1]["observability"]["incidentTracking"],
        true
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
