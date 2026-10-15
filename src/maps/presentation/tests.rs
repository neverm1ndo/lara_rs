use std::{future, path::PathBuf, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    http::{
        Method, Request, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
};
use chrono::{Duration, Utc};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

use crate::{
    auth::{
        application::authenticate_jwt::{AuthenticateBearerToken, AuthenticationError},
        domain::models::{AuthenticatedPrincipal, AuthenticatedUser, SessionId},
        presentation::extractors::JwtExtractorState,
    },
    maps::{
        application::file_service::MapsFileService,
        infrastructure::file_service::LocalMapsFileService,
        presentation::{routes::router, state::MapsState},
    },
    shared::{
        file_storage::{
            guard::NoBackupProvider,
            local::{FileStorageLimits, LocalFileStorage},
            upload::MultipartUploadLimits,
        },
        user_role::UserRole,
    },
};

const BOUNDARY: &str = "lara-maps-http-boundary";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("lara-maps-http-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Authenticator(Result<AuthenticatedPrincipal, AuthenticationError>);

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
        Box::pin(future::ready(self.0.clone()))
    }
}

#[derive(Clone)]
struct TestState {
    authenticator: Arc<dyn AuthenticateBearerToken>,
    service: Arc<dyn MapsFileService>,
    upload_limits: MultipartUploadLimits,
}

impl JwtExtractorState for TestState {
    fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
        Arc::clone(&self.authenticator)
    }
}

impl MapsState for TestState {
    fn maps_file_service(&self) -> Arc<dyn MapsFileService> {
        Arc::clone(&self.service)
    }

    fn maps_upload_limits(&self) -> MultipartUploadLimits {
        self.upload_limits
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

async fn app(
    directory: &TestDirectory,
    authentication: Result<AuthenticatedPrincipal, AuthenticationError>,
    upload_limits: MultipartUploadLimits,
) -> axum::Router {
    let storage = LocalFileStorage::open(
        directory.path(),
        FileStorageLimits::new(16, 1_000, 1024 * 1024).unwrap(),
    )
    .await
    .unwrap();
    let service = LocalMapsFileService::new(storage, Arc::new(NoBackupProvider));
    let state = TestState {
        authenticator: Arc::new(Authenticator(authentication)),
        service: Arc::new(service),
        upload_limits,
    };

    router::<TestState>().with_state(state).split_for_parts().0
}

fn default_limits() -> MultipartUploadLimits {
    MultipartUploadLimits::new(50, 1024 * 1024, 10 * 1024 * 1024).unwrap()
}

fn authorized_request(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(AUTHORIZATION, "Bearer signed.jwt")
        .body(Body::empty())
        .unwrap()
}

fn multipart(files: &[(&str, &str, &[u8])]) -> (String, Vec<u8>) {
    let mut body = Vec::new();
    for (field_name, file_name, bytes) in files {
        body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{field_name}\"; filename=\"{file_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={BOUNDARY}"), body)
}

fn upload_request(method: Method, files: &[(&str, &str, &[u8])]) -> Request<Body> {
    let (content_type, body) = multipart(files);
    Request::builder()
        .method(method)
        .uri("/files")
        .header(AUTHORIZATION, "Bearer signed.jwt")
        .header(CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn endpoints_allow_developer_and_mapper_but_reject_other_or_missing_sessions() {
    let directory = TestDirectory::new();

    for role in [UserRole::DEVELOPER, UserRole::MAPPER] {
        let response = app(&directory, Ok(principal(role)), default_limits())
            .await
            .oneshot(authorized_request("/tree"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let forbidden = app(
        &directory,
        Ok(principal(UserRole::CONFIGURATOR)),
        default_limits(),
    )
    .await
    .oneshot(authorized_request("/tree"))
    .await
    .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let missing = Request::builder().uri("/tree").body(Body::empty()).unwrap();
    let unauthorized = app(
        &directory,
        Ok(principal(UserRole::MAPPER)),
        default_limits(),
    )
    .await
    .oneshot(missing)
    .await
    .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn tree_and_read_endpoints_preserve_nested_files_and_exact_bytes() {
    let directory = TestDirectory::new();
    std::fs::create_dir_all(directory.path().join("city/interiors")).unwrap();
    std::fs::create_dir(directory.path().join("ignored")).unwrap();
    let map_bytes = vec![0, 0xff, 0x98, b'<', b'>'];
    std::fs::write(
        directory.path().join("city/interiors/shop.map.off"),
        &map_bytes,
    )
    .unwrap();
    std::fs::write(directory.path().join("city/notes.xml"), b"ignored").unwrap();
    std::fs::write(directory.path().join("ignored/readme.txt"), b"ignored").unwrap();
    let app = app(
        &directory,
        Ok(principal(UserRole::MAPPER)),
        default_limits(),
    )
    .await;

    let tree = app
        .clone()
        .oneshot(authorized_request("/tree"))
        .await
        .unwrap();
    assert_eq!(tree.status(), StatusCode::OK);
    let tree = json_body(tree).await;
    assert_eq!(tree["entries"].as_array().unwrap().len(), 1);
    assert_eq!(tree["entries"][0]["path"], "city");
    assert_eq!(
        tree["entries"][0]["children"][0]["children"][0]["path"],
        "city/interiors/shop.map.off"
    );

    let read = app
        .oneshot(authorized_request(
            "/files?path=city%2Finteriors%2Fshop.map.off",
        ))
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(read.headers()["content-type"], "application/xml");
    assert_eq!(
        read.headers()["content-length"],
        map_bytes.len().to_string()
    );
    let body = to_bytes(read.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], map_bytes);
}

#[tokio::test]
async fn multipart_crud_supports_multiple_nested_maps_and_returns_events() {
    let directory = TestDirectory::new();
    std::fs::create_dir(directory.path().join("city")).unwrap();
    std::fs::create_dir(directory.path().join("archive")).unwrap();
    let app = app(
        &directory,
        Ok(principal(UserRole::DEVELOPER)),
        default_limits(),
    )
    .await;

    let created = app
        .clone()
        .oneshot(upload_request(
            Method::POST,
            &[
                ("files", "root.map", b"root-v1"),
                ("files", "city/race.map.off", b"race-v1"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = json_body(created).await;
    assert_eq!(created["events"].as_array().unwrap().len(), 2);
    assert!(
        created["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|event| event["eventType"] == "maps.file-changed.v1")
    );
    assert_eq!(
        std::fs::read(directory.path().join("city/race.map.off")).unwrap(),
        b"race-v1"
    );

    let overwritten = app
        .clone()
        .oneshot(upload_request(
            Method::PUT,
            &[
                ("files", "root.map", b"root-v2"),
                ("files", "city/race.map.off", b"race-v2"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(overwritten.status(), StatusCode::OK);
    assert_eq!(
        std::fs::read(directory.path().join("root.map")).unwrap(),
        b"root-v2"
    );

    let renamed = Request::builder()
        .method(Method::PATCH)
        .uri("/files/rename")
        .header(AUTHORIZATION, "Bearer signed.jwt")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"source":"city/race.map.off","destination":"archive/race.map"}"#,
        ))
        .unwrap();
    let renamed = app.clone().oneshot(renamed).await.unwrap();
    assert_eq!(renamed.status(), StatusCode::OK);
    assert!(!directory.path().join("city/race.map.off").exists());
    assert!(directory.path().join("archive/race.map").exists());

    let deleted = Request::builder()
        .method(Method::DELETE)
        .uri("/files?path=archive%2Frace.map")
        .header(AUTHORIZATION, "Bearer signed.jwt")
        .body(Body::empty())
        .unwrap();
    let deleted = app.oneshot(deleted).await.unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
    assert!(!directory.path().join("archive/race.map").exists());
}

#[tokio::test]
async fn multipart_limits_are_enforced_before_the_service_is_called() {
    let directory = TestDirectory::new();
    let limits = MultipartUploadLimits::new(1, 4, 4).unwrap();
    let app = app(&directory, Ok(principal(UserRole::MAPPER)), limits).await;

    let too_many = app
        .clone()
        .oneshot(upload_request(
            Method::POST,
            &[("files", "one.map", b"1"), ("files", "two.map", b"2")],
        ))
        .await
        .unwrap();
    assert_eq!(too_many.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let too_large = app
        .oneshot(upload_request(
            Method::POST,
            &[("files", "large.map", b"12345")],
        ))
        .await
        .unwrap();
    assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!directory.path().join("one.map").exists());
    assert!(!directory.path().join("large.map").exists());
}

#[tokio::test]
async fn invalid_extensions_traversal_duplicates_and_wrong_fields_are_rejected() {
    let directory = TestDirectory::new();
    let app = app(
        &directory,
        Ok(principal(UserRole::DEVELOPER)),
        default_limits(),
    )
    .await;

    for files in [
        vec![("files", "race.xml", b"xml".as_slice())],
        vec![("files", "../race.map", b"escape".as_slice())],
        vec![("file", "race.map", b"wrong-field".as_slice())],
        vec![
            ("files", "city/Race.map", b"one".as_slice()),
            ("files", "CITY/race.MAP", b"two".as_slice()),
        ],
    ] {
        let response = app
            .clone()
            .oneshot(upload_request(Method::POST, &files))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    let traversal = app
        .oneshot(authorized_request("/files?path=..%2Frace.map"))
        .await
        .unwrap();
    assert_eq!(traversal.status(), StatusCode::BAD_REQUEST);
    assert!(!directory.path().join("race.map").exists());
}
