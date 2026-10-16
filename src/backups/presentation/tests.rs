use std::{
    fs,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration as StdDuration,
};

use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header::AUTHORIZATION},
};
use chrono::{DateTime, Duration, TimeZone, Utc};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

use super::{routes::router, state::BackupsState};
use crate::{
    auth::{
        application::authenticate_jwt::{AuthenticateBearerToken, AuthenticationError},
        domain::models::{AuthenticatedPrincipal, AuthenticatedUser, SessionId},
        presentation::extractors::JwtExtractorState,
    },
    backups::{
        application::{
            lifecycle::BackupLifecycleService,
            ports::{
                BackupClock, BackupDiffGenerator, BackupIdGenerator, BackupListQuery,
                BackupRepository, BackupRepositoryError, BackupRepositoryFuture,
            },
            preparation::{BackupPreparationPolicy, BackupPreparationService},
        },
        domain::{Backup, BackupId, BackupState, BackupVersion, SnapshotCompression},
        infrastructure::{
            diff_generator::DiffMatchPatchGenerator, restore_target::CapabilityBackupRestoreTarget,
            snapshot_store::LocalBackupSnapshotStore,
        },
    },
    maps::{
        application::file_service::{
            MapUpload, MapUploadBatch, MapsFileService, MapsRequestContext,
        },
        domain::{MAPS_STORAGE_NAMESPACE, MapAccess, MapFilePath, MapFilePolicy},
        infrastructure::file_service::LocalMapsFileService,
    },
    shared::{
        file_storage::{
            content::FileContentClassifier,
            local::{FileStorageLimits, LocalFileStorage},
            mutation::{MutationActor, MutationId, StorageNamespace},
            path::RelativeStoragePath,
        },
        user_role::UserRole,
    },
};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("lara-backups-{label}-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct MemoryBackupRepository(Mutex<Vec<Backup>>);

impl MemoryBackupRepository {
    fn available(&self) -> Vec<Backup> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|backup| {
                matches!(
                    backup.state(),
                    BackupState::Available | BackupState::Restoring { .. }
                )
            })
            .cloned()
            .collect()
    }
}

impl BackupRepository for MemoryBackupRepository {
    fn insert<'a>(&'a self, backup: &'a Backup) -> BackupRepositoryFuture<'a, ()> {
        Box::pin(async move {
            let mut backups = self.0.lock().unwrap();
            if backups
                .iter()
                .any(|stored| stored.mutation_id() == backup.mutation_id())
            {
                return Err(BackupRepositoryError::AlreadyExists);
            }
            backups.push(backup.clone());
            Ok(())
        })
    }

    fn find_by_id<'a>(&'a self, backup_id: BackupId) -> BackupRepositoryFuture<'a, Option<Backup>> {
        Box::pin(async move {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .find(|backup| backup.id() == backup_id)
                .cloned())
        })
    }

    fn find_by_mutation_id<'a>(
        &'a self,
        mutation_id: MutationId,
    ) -> BackupRepositoryFuture<'a, Option<Backup>> {
        Box::pin(async move {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .find(|backup| backup.mutation_id() == mutation_id)
                .cloned())
        })
    }

    fn list<'a>(&'a self, query: BackupListQuery) -> BackupRepositoryFuture<'a, Vec<Backup>> {
        Box::pin(async move {
            let mut backups = self.available();
            backups.sort_by(|left, right| {
                right
                    .created_at()
                    .cmp(&left.created_at())
                    .then_with(|| right.id().to_string().cmp(&left.id().to_string()))
            });
            if let Some(cursor) = query.cursor {
                backups.retain(|backup| {
                    backup.created_at() < cursor.created_at
                        || (backup.created_at() == cursor.created_at
                            && backup.id().to_string() < cursor.backup_id.to_string())
                });
            }
            backups.truncate(query.limit);
            Ok(backups)
        })
    }

    fn find_expired<'a>(
        &'a self,
        _at: DateTime<Utc>,
        _limit: usize,
    ) -> BackupRepositoryFuture<'a, Vec<Backup>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn find_stale_preparations<'a>(
        &'a self,
        _at: DateTime<Utc>,
        _limit: usize,
    ) -> BackupRepositoryFuture<'a, Vec<Backup>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn find_stale_operations<'a>(
        &'a self,
        _at: DateTime<Utc>,
        _limit: usize,
    ) -> BackupRepositoryFuture<'a, Vec<Backup>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn save<'a>(
        &'a self,
        backup: &'a Backup,
        expected_version: BackupVersion,
    ) -> BackupRepositoryFuture<'a, ()> {
        Box::pin(async move {
            let mut backups = self.0.lock().unwrap();
            let Some(stored) = backups.iter_mut().find(|stored| stored.id() == backup.id()) else {
                return Err(BackupRepositoryError::ConcurrentModification);
            };
            if stored.version() != expected_version
                || backup.version().get() != expected_version.get() + 1
            {
                return Err(BackupRepositoryError::ConcurrentModification);
            }
            *stored = backup.clone();
            Ok(())
        })
    }

    fn delete<'a>(
        &'a self,
        backup_id: BackupId,
        expected_version: BackupVersion,
    ) -> BackupRepositoryFuture<'a, ()> {
        Box::pin(async move {
            let mut backups = self.0.lock().unwrap();
            let Some(position) = backups.iter().position(|backup| {
                backup.id() == backup_id && backup.version() == expected_version
            }) else {
                return Err(BackupRepositoryError::ConcurrentModification);
            };
            backups.remove(position);
            Ok(())
        })
    }
}

#[derive(Clone, Copy)]
struct FixedClock(DateTime<Utc>);

impl BackupClock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

#[derive(Clone, Copy)]
struct FixedBackupId(BackupId);

impl BackupIdGenerator for FixedBackupId {
    fn next_id(&self) -> BackupId {
        self.0
    }
}

struct Authenticator;

impl AuthenticateBearerToken for Authenticator {
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<
        Box<dyn Future<Output = Result<AuthenticatedPrincipal, AuthenticationError>> + Send + 'a>,
    > {
        Box::pin(async move {
            if token != "valid.jwt" {
                return Err(AuthenticationError::Unauthorized);
            }
            Ok(AuthenticatedPrincipal {
                user: AuthenticatedUser {
                    id: 42,
                    username: "neo".into(),
                    main_group: UserRole::Mapper,
                    permissions: vec![UserRole::Mapper],
                    avatar: None,
                },
                session_id: SessionId::new("session-1").unwrap(),
                token_expires_at: Utc::now() + Duration::minutes(5),
            })
        })
    }
}

#[derive(Clone)]
struct TestState {
    authenticator: Arc<dyn AuthenticateBearerToken>,
    backups: Arc<BackupLifecycleService>,
}

impl JwtExtractorState for TestState {
    fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
        Arc::clone(&self.authenticator)
    }
}

impl BackupsState for TestState {
    fn backup_lifecycle_service(&self) -> Arc<BackupLifecycleService> {
        Arc::clone(&self.backups)
    }
}

struct Harness {
    _game_directory: TestDirectory,
    _snapshot_directory: TestDirectory,
    app: axum::Router,
    maps: LocalMapsFileService,
    map_path: PathBuf,
    repository: Arc<MemoryBackupRepository>,
    backup_id: BackupId,
}

impl Harness {
    async fn new(initial: &[u8]) -> Self {
        let game_directory = TestDirectory::new("game");
        let snapshot_directory = TestDirectory::new("snapshots");
        fs::write(game_directory.path().join("race.map"), initial).unwrap();
        let storage = LocalFileStorage::open(
            game_directory.path(),
            FileStorageLimits::new(8, 100, 1024 * 1024).unwrap(),
        )
        .await
        .unwrap();
        let repository = Arc::new(MemoryBackupRepository::default());
        let snapshots = Arc::new(
            LocalBackupSnapshotStore::initialize(snapshot_directory.path(), 1)
                .await
                .unwrap(),
        );
        let clock = Arc::new(FixedClock(Utc.timestamp_opt(1_700_000_000, 0).unwrap()));
        let backup_id = BackupId::new();
        let diff: Arc<dyn BackupDiffGenerator> = Arc::new(
            DiffMatchPatchGenerator::from_encoding_label(
                true,
                1024 * 1024,
                StdDuration::from_secs(1),
                "windows-1251",
            )
            .unwrap(),
        );
        let provider = Arc::new(BackupPreparationService::new(
            repository.clone(),
            snapshots.clone(),
            diff,
            clock.clone(),
            Arc::new(FixedBackupId(backup_id)),
            FileContentClassifier::new(std::iter::empty::<String>(), std::iter::empty::<String>())
                .unwrap(),
            BackupPreparationPolicy::new(
                StdDuration::from_secs(3600),
                StdDuration::from_secs(60),
                SnapshotCompression::Gzip,
                1,
            )
            .unwrap(),
        ));
        let maps = LocalMapsFileService::with_required_backups(storage.clone(), provider);
        let restore_target = CapabilityBackupRestoreTarget::new().register(
            StorageNamespace::new(MAPS_STORAGE_NAMESPACE).unwrap(),
            storage,
            |path| MapFilePolicy.recognizes(path),
        );
        let lifecycle = Arc::new(
            BackupLifecycleService::new(
                repository.clone(),
                snapshots,
                Arc::new(restore_target),
                clock,
                StdDuration::from_secs(60),
            )
            .unwrap(),
        );
        let state = TestState {
            authenticator: Arc::new(Authenticator),
            backups: lifecycle,
        };
        let app = router::<TestState>().with_state(state).split_for_parts().0;
        let map_path = game_directory.path().join("race.map");

        Self {
            _game_directory: game_directory,
            _snapshot_directory: snapshot_directory,
            app,
            maps,
            map_path,
            repository,
            backup_id,
        }
    }

    async fn overwrite(&self, replacement: &[u8]) {
        let context = MapsRequestContext::new(
            MapAccess::authorize(UserRole::Mapper, &[]).unwrap(),
            MutationActor::new("42", Some("session-1".into())).unwrap(),
        );
        let batch = MapUploadBatch::new(vec![MapUpload::new(
            MapFilePath::new(RelativeStoragePath::new("race.map").unwrap()).unwrap(),
            replacement.to_vec(),
        )])
        .unwrap();
        self.maps.overwrite_many(context, batch).await.unwrap();
    }

    async fn request(
        &self,
        method: Method,
        uri: &str,
        authenticated: bool,
    ) -> axum::response::Response {
        let mut builder = Request::builder().method(method).uri(uri);
        if authenticated {
            builder = builder.header(AUTHORIZATION, "Bearer valid.jwt");
        }
        self.app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }
}

async fn json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn map_mutation_is_listed_downloaded_restored_and_deleted_through_http() {
    let original = "<map name=\"Старая\"/>".as_bytes();
    let replacement = "<map name=\"Новая\"/>".as_bytes();
    let harness = Harness::new(original).await;

    harness.overwrite(replacement).await;
    assert_eq!(fs::read(&harness.map_path).unwrap(), replacement);

    let response = harness.request(Method::GET, "/list", true).await;
    assert_eq!(response.status(), StatusCode::OK);
    let list = json(response).await;
    assert_eq!(list["backups"].as_array().unwrap().len(), 1);
    assert_eq!(list["backups"][0]["id"], harness.backup_id.to_string());
    assert_eq!(list["backups"][0]["initiatedBy"], 42);
    assert_eq!(list["backups"][0]["namespace"], MAPS_STORAGE_NAMESPACE);
    assert_eq!(list["backups"][0]["path"], "race.map");
    assert_eq!(list["backups"][0]["diff"]["kind"], "diff_match_patch");
    assert_eq!(list["backups"][0]["snapshot"]["binary"], false);

    let response = harness
        .request(Method::GET, &format!("/backup/{}", harness.backup_id), true)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let downloaded = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(downloaded.as_ref(), original);

    let response = harness
        .request(
            Method::POST,
            &format!("/restore/{}", harness.backup_id),
            true,
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(fs::read(&harness.map_path).unwrap(), original);

    let response = harness
        .request(
            Method::DELETE,
            &format!("/backup/{}", harness.backup_id),
            true,
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(harness.repository.available().is_empty());

    let response = harness
        .request(Method::GET, &format!("/backup/{}", harness.backup_id), true)
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn binary_map_keeps_exact_snapshot_and_exposes_skipped_diff() {
    let mut original = vec![b'x'; 512];
    original[..200].fill(0);
    let replacement = b"replacement";
    let harness = Harness::new(&original).await;

    harness.overwrite(replacement).await;

    let list = json(harness.request(Method::GET, "/list", true).await).await;
    assert_eq!(list["backups"][0]["snapshot"]["binary"], true);
    assert_eq!(list["backups"][0]["diff"]["kind"], "skipped");
    assert_eq!(list["backups"][0]["diff"]["reason"], "binary_content");

    let response = harness
        .request(Method::GET, &format!("/backup/{}", harness.backup_id), true)
        .await;
    let downloaded = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(downloaded.as_ref(), original);
}

#[tokio::test]
async fn endpoints_require_authentication_and_validate_identifiers_and_cursors() {
    let harness = Harness::new(b"original").await;

    assert_eq!(
        harness.request(Method::GET, "/list", false).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        harness
            .request(Method::GET, "/backup/not-a-uuid", true)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        harness
            .request(Method::GET, "/list?limit=0", true)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        harness
            .request(
                Method::GET,
                "/list?cursorCreatedAt=2025-01-01T00%3A00%3A00Z",
                true,
            )
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
}
