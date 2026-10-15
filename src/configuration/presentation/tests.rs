use std::{
    future,
    sync::{Arc, Mutex},
};

use axum::{
    body::{Body, to_bytes},
    http::{
        Method, Request, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
};
use chrono::{Duration, Utc};
use encoding_rs::{Encoding, UTF_8, WINDOWS_1251};
use serde_json::Value;
use tower::ServiceExt;

use crate::{
    auth::{
        application::authenticate_jwt::{AuthenticateBearerToken, AuthenticationError},
        domain::models::{AuthenticatedPrincipal, AuthenticatedUser, SessionId},
        presentation::extractors::JwtExtractorState,
    },
    configuration::{
        application::file_service::{
            ConfigurationFileContent, ConfigurationFileService, ConfigurationFileServiceError,
            ConfigurationRequestContext, ConfigurationServiceFuture, ConfigurationTextFile,
            ConfigurationTreeEntry, ConfigurationTreeEntryKind,
        },
        domain::ConfigurationFileChanged,
        presentation::{
            authorization::ConfigurationAuthorizationState, routes::router,
            state::ConfigurationState,
        },
    },
    shared::{
        file_storage::{
            event::FileChanged,
            mutation::{FileMutationKind, FileRevision, MutationId, StorageNamespace},
            path::RelativeStoragePath,
        },
        user_role::UserRole,
    },
};

struct Authenticator(AuthenticatedPrincipal);

impl AuthenticateBearerToken for Authenticator {
    fn authenticate<'a>(
        &'a self,
        _token: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<AuthenticatedPrincipal, AuthenticationError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(future::ready(Ok(self.0.clone())))
    }
}

struct StubService;

impl ConfigurationFileService for StubService {
    fn tree<'a>(
        &'a self,
        _context: ConfigurationRequestContext,
    ) -> ConfigurationServiceFuture<'a, Vec<ConfigurationTreeEntry>> {
        Box::pin(future::ready(Ok(vec![ConfigurationTreeEntry {
            path: RelativeStoragePath::new("server.cfg").unwrap(),
            name: "server.cfg".into(),
            kind: ConfigurationTreeEntryKind::Text,
            size: Some(15),
            modified_at: None,
            children: vec![],
        }])))
    }

    fn open_text<'a>(
        &'a self,
        _context: ConfigurationRequestContext,
        _path: RelativeStoragePath,
    ) -> ConfigurationServiceFuture<'a, ConfigurationTextFile> {
        Box::pin(future::ready(Ok(ConfigurationTextFile {
            // "Привет" encoded as Windows-1251.
            reader: Box::pin(std::io::Cursor::new(vec![
                0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2,
            ])),
            content_length: Some(6),
            file_name: "server.cfg".into(),
            encoding_label: "windows-1251".into(),
        })))
    }

    fn create<'a>(
        &'a self,
        _context: ConfigurationRequestContext,
        _path: RelativeStoragePath,
        _content: ConfigurationFileContent,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged> {
        unavailable()
    }

    fn overwrite<'a>(
        &'a self,
        _context: ConfigurationRequestContext,
        _path: RelativeStoragePath,
        _content: ConfigurationFileContent,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged> {
        unavailable()
    }

    fn delete<'a>(
        &'a self,
        _context: ConfigurationRequestContext,
        _path: RelativeStoragePath,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged> {
        unavailable()
    }

    fn rename<'a>(
        &'a self,
        _context: ConfigurationRequestContext,
        _source: RelativeStoragePath,
        _destination: RelativeStoragePath,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged> {
        unavailable()
    }
}

fn unavailable<'a, T: Send + 'a>() -> ConfigurationServiceFuture<'a, T> {
    Box::pin(future::ready(Err(
        ConfigurationFileServiceError::Unavailable,
    )))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MutationCall {
    Create(RelativeStoragePath, Vec<u8>),
    Overwrite(RelativeStoragePath, Vec<u8>),
    Delete(RelativeStoragePath),
    Rename(RelativeStoragePath, RelativeStoragePath),
}

struct RecordingMutationService {
    calls: Arc<Mutex<Vec<MutationCall>>>,
}

impl ConfigurationFileService for RecordingMutationService {
    fn tree<'a>(
        &'a self,
        _context: ConfigurationRequestContext,
    ) -> ConfigurationServiceFuture<'a, Vec<ConfigurationTreeEntry>> {
        unavailable()
    }

    fn open_text<'a>(
        &'a self,
        _context: ConfigurationRequestContext,
        _path: RelativeStoragePath,
    ) -> ConfigurationServiceFuture<'a, ConfigurationTextFile> {
        unavailable()
    }

    fn create<'a>(
        &'a self,
        context: ConfigurationRequestContext,
        path: RelativeStoragePath,
        content: ConfigurationFileContent,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged> {
        self.calls
            .lock()
            .unwrap()
            .push(MutationCall::Create(path.clone(), content.into_bytes()));
        Box::pin(future::ready(Ok(mutation_event(
            &context,
            FileMutationKind::Create,
            None,
            Some(path),
        ))))
    }

    fn overwrite<'a>(
        &'a self,
        context: ConfigurationRequestContext,
        path: RelativeStoragePath,
        content: ConfigurationFileContent,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged> {
        self.calls
            .lock()
            .unwrap()
            .push(MutationCall::Overwrite(path.clone(), content.into_bytes()));
        Box::pin(future::ready(Ok(mutation_event(
            &context,
            FileMutationKind::Overwrite,
            Some(path.clone()),
            Some(path),
        ))))
    }

    fn delete<'a>(
        &'a self,
        context: ConfigurationRequestContext,
        path: RelativeStoragePath,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged> {
        self.calls
            .lock()
            .unwrap()
            .push(MutationCall::Delete(path.clone()));
        Box::pin(future::ready(Ok(mutation_event(
            &context,
            FileMutationKind::Delete,
            Some(path),
            None,
        ))))
    }

    fn rename<'a>(
        &'a self,
        context: ConfigurationRequestContext,
        source: RelativeStoragePath,
        destination: RelativeStoragePath,
    ) -> ConfigurationServiceFuture<'a, ConfigurationFileChanged> {
        self.calls
            .lock()
            .unwrap()
            .push(MutationCall::Rename(source.clone(), destination.clone()));
        Box::pin(future::ready(Ok(mutation_event(
            &context,
            FileMutationKind::Rename,
            Some(source),
            Some(destination),
        ))))
    }
}

fn mutation_event(
    context: &ConfigurationRequestContext,
    kind: FileMutationKind,
    source: Option<RelativeStoragePath>,
    destination: Option<RelativeStoragePath>,
) -> ConfigurationFileChanged {
    let revision = || FileRevision::from_metadata(6, Utc::now());
    let (previous_revision, current_revision) = match kind {
        FileMutationKind::Create => (None, Some(revision())),
        FileMutationKind::Overwrite | FileMutationKind::Rename => {
            (Some(revision()), Some(revision()))
        }
        FileMutationKind::Delete => (Some(revision()), None),
    };
    let storage_event = FileChanged::new(
        MutationId::new(),
        StorageNamespace::new("configuration").unwrap(),
        context.actor().clone(),
        Utc::now(),
        kind,
        source,
        destination,
        previous_revision,
        current_revision,
        None,
    );
    ConfigurationFileChanged::from_storage(&storage_event, context.access()).unwrap()
}

#[derive(Clone)]
struct TestState {
    authenticator: Arc<dyn AuthenticateBearerToken>,
    service: Arc<dyn ConfigurationFileService>,
    configurator_directory: RelativeStoragePath,
    encoding: &'static Encoding,
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

impl ConfigurationState for TestState {
    fn configuration_file_service(&self) -> Arc<dyn ConfigurationFileService> {
        Arc::clone(&self.service)
    }

    fn configuration_file_encoding(&self) -> &'static Encoding {
        self.encoding
    }
}

fn principal(role: UserRole) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        user: AuthenticatedUser {
            id: 42,
            username: "neo".into(),
            main_group: role,
            permissions: vec![],
            avatar: None,
        },
        session_id: SessionId::new("session-1").unwrap(),
        token_expires_at: Utc::now() + Duration::minutes(5),
    }
}

fn app_with_service(role: UserRole, service: Arc<dyn ConfigurationFileService>) -> axum::Router {
    app_with_service_and_encoding(role, service, WINDOWS_1251)
}

fn app_with_service_and_encoding(
    role: UserRole,
    service: Arc<dyn ConfigurationFileService>,
    encoding: &'static Encoding,
) -> axum::Router {
    let state = TestState {
        authenticator: Arc::new(Authenticator(principal(role))),
        service,
        configurator_directory: RelativeStoragePath::new("scriptfiles/config").unwrap(),
        encoding,
    };
    router::<TestState>().with_state(state).split_for_parts().0
}

fn multipart_file(bytes: &[u8]) -> (String, Vec<u8>) {
    const BOUNDARY: &str = "lara-configuration-boundary";
    let mut body = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"upload.cfg\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={BOUNDARY}"), body)
}

fn app(role: UserRole) -> axum::Router {
    app_with_service(role, Arc::new(StubService))
}

fn authorized_request(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(AUTHORIZATION, "Bearer signed.jwt")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn tree_endpoint_returns_the_role_scoped_tree() {
    let response = app(UserRole::DEVELOPER)
        .oneshot(authorized_request("/tree"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["entries"][0]["path"], "server.cfg");
    assert_eq!(value["entries"][0]["kind"], "text");
}

#[tokio::test]
async fn read_endpoint_streams_windows_1251_bytes_without_transcoding() {
    let response = app(UserRole::CONFIGURATOR)
        .oneshot(authorized_request("/files?path=server.cfg"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "text/plain; charset=windows-1251"
    );
    assert_eq!(response.headers()["content-length"], "6");
    assert!(
        response.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .contains("server.cfg")
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], &[0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2]);
}

#[tokio::test]
async fn mutation_endpoints_preserve_legacy_bytes_and_dispatch_typed_commands() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let service: Arc<dyn ConfigurationFileService> = Arc::new(RecordingMutationService {
        calls: Arc::clone(&calls),
    });
    let cp1251 = vec![0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2];
    let (multipart_content_type, multipart_body) = multipart_file(&cp1251);

    let create = Request::builder()
        .method(Method::POST)
        .uri("/files?path=new.cfg")
        .header(AUTHORIZATION, "Bearer signed.jwt")
        .header(CONTENT_TYPE, &multipart_content_type)
        .body(Body::from(multipart_body))
        .unwrap();
    let response = app_with_service(UserRole::DEVELOPER, Arc::clone(&service))
        .oneshot(create)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let response_json: Value = serde_json::from_slice(&response_body).unwrap();
    assert_eq!(response_json["eventType"], "configuration.file-changed.v1");

    let (multipart_content_type, multipart_body) = multipart_file(&cp1251);
    let overwrite = Request::builder()
        .method(Method::PUT)
        .uri("/files?path=server.cfg")
        .header(AUTHORIZATION, "Bearer signed.jwt")
        .header(CONTENT_TYPE, multipart_content_type)
        .body(Body::from(multipart_body))
        .unwrap();
    let response = app_with_service(UserRole::DEVELOPER, Arc::clone(&service))
        .oneshot(overwrite)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let delete = Request::builder()
        .method(Method::DELETE)
        .uri("/files?path=old.cfg")
        .header(AUTHORIZATION, "Bearer signed.jwt")
        .body(Body::empty())
        .unwrap();
    let response = app_with_service(UserRole::DEVELOPER, Arc::clone(&service))
        .oneshot(delete)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let rename = Request::builder()
        .method(Method::PATCH)
        .uri("/files/rename")
        .header(AUTHORIZATION, "Bearer signed.jwt")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"source":"old-name.cfg","destination":"new-name.cfg"}"#,
        ))
        .unwrap();
    let response = app_with_service(UserRole::DEVELOPER, service)
        .oneshot(rename)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        *calls.lock().unwrap(),
        vec![
            MutationCall::Create(RelativeStoragePath::new("new.cfg").unwrap(), cp1251.clone()),
            MutationCall::Overwrite(RelativeStoragePath::new("server.cfg").unwrap(), cp1251),
            MutationCall::Delete(RelativeStoragePath::new("old.cfg").unwrap()),
            MutationCall::Rename(
                RelativeStoragePath::new("old-name.cfg").unwrap(),
                RelativeStoragePath::new("new-name.cfg").unwrap()
            ),
        ]
    );
}

#[tokio::test]
async fn upload_rejects_bytes_invalid_for_the_server_configured_encoding() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let service: Arc<dyn ConfigurationFileService> = Arc::new(RecordingMutationService {
        calls: Arc::clone(&calls),
    });
    let (content_type, body) = multipart_file(&[0xff]);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/files?path=new.cfg")
        .header(AUTHORIZATION, "Bearer signed.jwt")
        .header(CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .unwrap();

    let response = app_with_service_and_encoding(UserRole::DEVELOPER, service, UTF_8)
        .oneshot(request)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn upload_requires_exactly_one_file_field() {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/files?path=new.cfg")
        .header(AUTHORIZATION, "Bearer signed.jwt")
        .header(CONTENT_TYPE, "multipart/form-data; boundary=empty")
        .body(Body::from("--empty--\r\n"))
        .unwrap();

    let response = app(UserRole::DEVELOPER).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn endpoints_reject_users_outside_the_two_allowed_roles() {
    let response = app(UserRole::ADMIN)
        .oneshot(authorized_request("/tree"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn read_endpoint_rejects_traversal_before_calling_the_service() {
    let response = app(UserRole::DEVELOPER)
        .oneshot(authorized_request("/files?path=../server.cfg"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
