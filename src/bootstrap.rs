use std::{error::Error, sync::Arc, time::Duration};

use axum::Router;
use mongodb::Client;
use sea_orm::Database;
use tokio::sync::watch;
use tracing::info;
use utoipa_axum::router::OpenApiRouter;

use crate::{
    app_state::AppState,
    auth::{
        self,
        application::{authenticate_jwt::JwtAuthenticationService, login::LoginService},
        infrastructure::{
            jwt::{Hs256JwtIssuer, Hs256JwtVerifier},
            legacy_md5_verifier::LegacyMd5Verifier,
            session_id_generator::UuidSessionIdGenerator,
            session_repository::MongoSessionRepository,
        },
    },
    backups::{
        self,
        application::{
            lifecycle::BackupLifecycleService,
            maintenance::{BackupMaintenancePolicy, BackupMaintenanceService},
            preparation::{BackupPreparationPolicy, BackupPreparationService},
        },
        domain::SnapshotCompression,
        infrastructure::{
            diff_generator::DiffMatchPatchGenerator,
            maintenance_worker::BackupMaintenanceWorker,
            repository::MongoBackupRepository,
            restore_target::CapabilityBackupRestoreTarget,
            runtime::{SystemBackupClock, UuidBackupIdGenerator},
            snapshot_store::LocalBackupSnapshotStore,
        },
    },
    maps::{
        self,
        domain::{MAPS_STORAGE_NAMESPACE, MapFilePolicy},
        infrastructure::file_service::LocalMapsFileService,
    },
    shared::{
        config::{AppConfig, model::BackupCompression},
        file_storage::{
            content::FileContentClassifier,
            local::{FileStorageLimits, LocalFileStorage},
            mutation::StorageNamespace,
            path::RelativeStoragePath,
            upload::MultipartUploadLimits,
        },
    },
    user::infrastructure::{
        authenticated_user_repository::SeaOrmAuthenticatedUserRepository,
        login_user_repository::SeaOrmLoginUserRepository,
    },
};

type BootstrapError = Box<dyn Error + Send + Sync>;

pub async fn run(config: AppConfig) -> Result<(), BootstrapError> {
    let bind_address = config.server.bind_address;
    let application = build_application(config).await?;
    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let maintenance = tokio::spawn(application.maintenance_worker.run(shutdown_rx));

    info!(address = %bind_address, "HTTP server listening");
    let server_result = axum::serve(listener, application.router)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    let _ = shutdown_tx.send(true);
    maintenance.await?;
    server_result?;
    Ok(())
}

struct BuiltApplication {
    router: Router,
    maintenance_worker: BackupMaintenanceWorker,
}

async fn build_application(config: AppConfig) -> Result<BuiltApplication, BootstrapError> {
    let configurator_directory =
        RelativeStoragePath::try_from(config.configuration.files.configurator_directory.as_path())?;
    let maps_directory = RelativeStoragePath::try_from(config.maps.files.directory.as_path())?;
    let storage_limits = FileStorageLimits::new(
        config.game_server.storage.max_tree_depth,
        config.game_server.storage.max_tree_entries,
        config.game_server.storage.max_stream_size_bytes,
    )?;
    let maps_upload_limits = MultipartUploadLimits::new(
        config.maps.upload.max_files_per_request,
        config.maps.upload.max_file_size_bytes,
        config.maps.upload.max_total_size_bytes,
    )?;
    let game_server_storage =
        LocalFileStorage::open(&config.game_server.storage.root, storage_limits).await?;
    let maps_storage = game_server_storage.scoped(&maps_directory).await?;

    let mysql = Database::connect(config.mysql.url.expose_secret()).await?;
    let mongo = Client::with_uri_str(config.mongodb.uri.expose_secret()).await?;
    let mongo_database = mongo.database(&config.mongodb.database);

    let sessions = MongoSessionRepository::new(mongo_database.clone());
    sessions.ensure_indexes().await?;

    let backup_repository = Arc::new(MongoBackupRepository::new(mongo_database));
    backup_repository.ensure_indexes().await?;
    let snapshot_store = Arc::new(
        LocalBackupSnapshotStore::initialize(
            &config.backups.storage.directory,
            config.backups.storage.compression_level,
        )
        .await?,
    );
    let diff_generator = Arc::new(DiffMatchPatchGenerator::from_encoding_label(
        config.backups.diff.enabled,
        config.backups.diff.max_input_size_bytes,
        Duration::from_millis(config.backups.diff.generation_timeout_ms),
        &config.configuration.files.fallback_encoding,
    )?);
    let clock = Arc::new(SystemBackupClock);
    let compression = match config.backups.storage.compression {
        BackupCompression::None => SnapshotCompression::None,
        BackupCompression::Gzip => SnapshotCompression::Gzip,
    };
    let backup_provider = Arc::new(BackupPreparationService::new(
        backup_repository.clone(),
        snapshot_store.clone(),
        diff_generator,
        clock.clone(),
        Arc::new(UuidBackupIdGenerator),
        FileContentClassifier::new(
            config.configuration.files.binary_extensions.clone(),
            config.configuration.files.binary_file_names.clone(),
        )?,
        BackupPreparationPolicy::new(
            Duration::from_secs(config.backups.retention.lifetime_seconds),
            Duration::from_secs(config.backups.retention.stale_preparation_seconds),
            compression,
            config.backups.storage.compression_threshold_bytes,
        )?,
    ));
    let maps_file_service =
        LocalMapsFileService::with_required_backups(maps_storage.clone(), backup_provider);

    let maps_namespace = StorageNamespace::new(MAPS_STORAGE_NAMESPACE)?;
    let restore_target = Arc::new(CapabilityBackupRestoreTarget::new().register(
        maps_namespace,
        maps_storage,
        |path| MapFilePolicy.recognizes(path),
    ));
    let backup_lifecycle_service = Arc::new(BackupLifecycleService::new(
        backup_repository.clone(),
        snapshot_store.clone(),
        restore_target,
        clock.clone(),
        Duration::from_secs(config.backups.retention.operation_lease_seconds),
    )?);
    let maintenance_service = Arc::new(BackupMaintenanceService::new(
        backup_repository,
        snapshot_store,
        clock,
        BackupMaintenancePolicy::new(
            config.backups.retention.cleanup_batch_size,
            config.backups.retention.max_concurrent_deletions,
            Duration::from_secs(config.backups.retention.operation_lease_seconds),
        )?,
    ));
    let maintenance_worker = BackupMaintenanceWorker::new(
        maintenance_service,
        Duration::from_secs(config.backups.retention.cleanup_interval_seconds),
    )?;

    let verifier = Hs256JwtVerifier::new(
        config.jwt.secret.expose_secret().as_bytes(),
        config.jwt.issuer.clone(),
        config.jwt.audience.clone(),
    )?;
    let issuer = Hs256JwtIssuer::new(
        config.jwt.secret.expose_secret().as_bytes(),
        config.jwt.issuer.clone(),
        config.jwt.audience.clone(),
    )?;
    let authenticated_users = SeaOrmAuthenticatedUserRepository::new(mysql.clone());
    let login_users = SeaOrmLoginUserRepository::new(mysql);
    let authenticator =
        JwtAuthenticationService::new(verifier, sessions.clone(), authenticated_users);
    let login_service = LoginService::new(
        LegacyMd5Verifier,
        login_users,
        sessions,
        UuidSessionIdGenerator,
        issuer,
        config.jwt.issuer,
        config.jwt.audience,
        config.jwt.ttl_seconds,
    )?;
    let state = AppState::new(
        authenticator,
        login_service,
        configurator_directory,
        maps_file_service,
        maps_upload_limits,
        backup_lifecycle_service,
    );

    let openapi = base_openapi_document();

    let (router, openapi) = OpenApiRouter::<AppState>::with_openapi(openapi)
        .nest("/auth", auth::presentation::router::<AppState>())
        .nest("/maps", maps::presentation::router::<AppState>())
        .nest("/backups", backups::presentation::router::<AppState>())
        .with_state(state)
        .split_for_parts();

    Ok(BuiltApplication {
        router: router.merge(auth::presentation::openapi_router(openapi)),
        maintenance_worker,
    })
}

fn base_openapi_document() -> utoipa::openapi::OpenApi {
    auth::presentation::openapi_document()
        .merge_from(maps::presentation::openapi_document())
        .merge_from(backups::presentation::openapi_document())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(error = %error, "failed to install shutdown signal handler");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use utoipa_axum::router::OpenApiRouter;

    use super::*;
    use crate::{
        auth::{
            application::{authenticate_jwt::AuthenticateBearerToken, login::Login},
            presentation::{extractors::JwtExtractorState, state::LoginState},
        },
        backups::{
            application::lifecycle::BackupLifecycleService, presentation::state::BackupsState,
        },
        maps::{application::file_service::MapsFileService, presentation::state::MapsState},
        shared::file_storage::upload::MultipartUploadLimits,
    };

    #[derive(Clone)]
    struct DocumentationState;

    impl JwtExtractorState for DocumentationState {
        fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
            panic!("documentation generation does not resolve authentication")
        }
    }

    impl LoginState for DocumentationState {
        fn login_service(&self) -> Arc<dyn Login> {
            panic!("documentation generation does not resolve application services")
        }
    }

    impl MapsState for DocumentationState {
        fn maps_file_service(&self) -> Arc<dyn MapsFileService> {
            panic!("documentation generation does not resolve application services")
        }

        fn maps_upload_limits(&self) -> MultipartUploadLimits {
            MultipartUploadLimits::new(50, 10 * 1024 * 1024, 50 * 1024 * 1024).unwrap()
        }
    }

    impl BackupsState for DocumentationState {
        fn backup_lifecycle_service(&self) -> Arc<BackupLifecycleService> {
            panic!("documentation generation does not resolve application services")
        }
    }

    #[test]
    fn global_openapi_document_contains_auth_and_maps_routes() {
        let document = OpenApiRouter::<DocumentationState>::with_openapi(base_openapi_document())
            .nest("/auth", auth::presentation::router())
            .nest("/maps", maps::presentation::router())
            .nest("/backups", backups::presentation::router())
            .into_openapi();
        let specification = serde_json::to_value(document).unwrap();

        assert_eq!(specification["openapi"], "3.1.0");
        assert!(specification["paths"]["/auth/login"]["post"].is_object());
        assert!(specification["paths"]["/auth/session"]["get"].is_object());
        assert!(specification["paths"]["/maps/tree"]["get"].is_object());
        assert!(specification["paths"]["/maps/files"]["post"].is_object());
        assert!(specification["paths"]["/backups/list"]["get"].is_object());
        assert!(specification["paths"]["/backups/backup/{backup_id}"]["get"].is_object());
        assert!(specification["paths"]["/backups/restore/{backup_id}"]["post"].is_object());
        assert!(specification["components"]["schemas"]["MapFileMutationsResponse"].is_object());
        assert_eq!(
            specification["components"]["securitySchemes"]["bearerAuth"]["scheme"],
            "bearer"
        );
    }
}
