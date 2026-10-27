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
        application::{
            authenticate_jwt::{JwtAuthenticationService, SessionProtectionPolicy},
            login::AuthenticatedSessionIssuer,
            mfa::{
                login::MfaLoginService,
                management::MfaManagementService,
                ports::{
                    MfaChallengeRepository, MfaChallengeTokenGenerator, MfaChallengeTokenHasher,
                    MfaClock, MfaFactorRepository, RecoveryCodeGenerator, RecoveryCodeHasher,
                    TotpSecretCipher, TotpSecretGenerator, TotpVerifier,
                },
                session_policy::MfaSessionProtectionPolicy,
                verification::MfaFactorVerificationService,
            },
        },
        infrastructure::{
            jwt::{Hs256JwtIssuer, Hs256JwtVerifier},
            legacy_md5_verifier::LegacyMd5Verifier,
            mfa_repository::{MongoMfaChallengeRepository, MongoMfaFactorRepository},
            mfa_security::{
                Aes256GcmTotpSecretCipher, Argon2RecoveryCodeHasher, OsMfaChallengeTokenGenerator,
                OsRecoveryCodeGenerator, OsTotpSecretGenerator, Rfc6238TotpVerifier,
                Sha256MfaChallengeTokenHasher, SystemMfaClock,
            },
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
    server_instances::{
        self,
        application::{
            lifecycle_service::LifecycleOperationService,
            registry::InstanceRegistry,
            runtime_state::{RuntimeStateReader, RuntimeStateWriter},
        },
        infrastructure::{
            config_registry::ConfiguredInstanceRegistry,
            lifecycle_operation_repository::MongoLifecycleOperationRepository,
            lifecycle_operation_support::{
                SystemLifecycleOperationClock, UuidLifecycleOperationIdGenerator,
            },
            runtime_state_store::InMemoryRuntimeStateStore,
            systemd_observer::{SystemdObservationTarget, SystemdObserverWorker},
            systemd_runtime::SystemdLifecycleRuntime,
        },
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
    user::{
        self,
        application::get_user::GetUserService,
        infrastructure::{
            authenticated_user_repository::SeaOrmAuthenticatedUserRepository,
            login_user_repository::SeaOrmLoginUserRepository,
            user_profile_repository::SeaOrmUserProfileRepository,
        },
    },
};

type BootstrapError = Box<dyn Error + Send + Sync>;
const CURRENT_MFA_ENCRYPTION_KEY_VERSION: u32 = 1;
const LIFECYCLE_OPERATION_TIMEOUT: Duration = Duration::from_secs(120);

pub async fn run(config: AppConfig) -> Result<(), BootstrapError> {
    let bind_address = config.server.bind_address;
    let application = build_application(config).await?;
    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let maintenance = tokio::spawn(application.maintenance_worker.run(shutdown_rx.clone()));
    let systemd_observer = application
        .systemd_observer
        .map(|worker| tokio::spawn(worker.run(shutdown_rx)));

    info!(address = %bind_address, "HTTP server listening");
    let server_result = axum::serve(listener, application.router)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    let _ = shutdown_tx.send(true);
    maintenance.await?;
    if let Some(observer) = systemd_observer {
        observer.await?;
    }
    server_result?;
    Ok(())
}

struct BuiltApplication {
    router: Router,
    maintenance_worker: BackupMaintenanceWorker,
    systemd_observer: Option<SystemdObserverWorker>,
}

async fn build_application(config: AppConfig) -> Result<BuiltApplication, BootstrapError> {
    let instance_registry = Arc::new(ConfiguredInstanceRegistry::from_config(
        &config.game_server,
    )?);
    let runtime_states = Arc::new(InMemoryRuntimeStateStore::new());
    let runtime_state_reader: Arc<dyn RuntimeStateReader> = runtime_states.clone();
    let runtime_state_writer: Arc<dyn RuntimeStateWriter> = runtime_states;
    let observation_targets: Vec<_> = instance_registry
        .systemd_managed()
        .map(|configured| {
            let descriptor = configured.descriptor();
            SystemdObservationTarget::new(
                descriptor.id().clone(),
                configured
                    .systemd_unit()
                    .expect("systemd-managed instances have a validated unit")
                    .as_str(),
                descriptor.observability().readiness(),
            )
        })
        .collect();
    let systemd_observer = (!observation_targets.is_empty())
        .then(|| SystemdObserverWorker::new(observation_targets, runtime_state_writer));
    info!(
        instance_count = instance_registry.list().len(),
        primary_instance = %instance_registry.primary().id(),
        "server instance registry loaded"
    );
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

    let mfa_factor_repository = MongoMfaFactorRepository::new(mongo_database.clone());
    mfa_factor_repository.ensure_indexes().await?;
    let mfa_challenge_repository = MongoMfaChallengeRepository::new(mongo_database.clone());
    mfa_challenge_repository.ensure_indexes().await?;
    let mfa_factors: Arc<dyn MfaFactorRepository> = Arc::new(mfa_factor_repository);
    let mfa_challenges: Arc<dyn MfaChallengeRepository> = Arc::new(mfa_challenge_repository);

    let lifecycle_operations = Arc::new(MongoLifecycleOperationRepository::new(
        mongo_database.clone(),
    ));
    lifecycle_operations.ensure_indexes().await?;
    let lifecycle_runtime = Arc::new(SystemdLifecycleRuntime::from_registry(
        instance_registry.as_ref(),
    ));
    let registry_port: Arc<dyn InstanceRegistry> = instance_registry.clone();
    let lifecycle_operation_service = Arc::new(LifecycleOperationService::new(
        registry_port.clone(),
        lifecycle_operations,
        lifecycle_runtime,
        runtime_state_reader.clone(),
        Arc::new(SystemLifecycleOperationClock),
        Arc::new(UuidLifecycleOperationIdGenerator),
        LIFECYCLE_OPERATION_TIMEOUT,
    )?);

    let totp_secret_generator: Arc<dyn TotpSecretGenerator> = Arc::new(OsTotpSecretGenerator);
    let totp_cipher: Arc<dyn TotpSecretCipher> = Arc::new(Aes256GcmTotpSecretCipher::from_hex(
        config.mfa.encryption_key.expose_secret(),
        CURRENT_MFA_ENCRYPTION_KEY_VERSION,
    )?);
    let totp_verifier: Arc<dyn TotpVerifier> = Arc::new(Rfc6238TotpVerifier::new(
        config.mfa.totp_period_seconds,
        config.mfa.totp_digits,
        config.mfa.allowed_clock_skew_steps,
    )?);
    let challenge_tokens: Arc<dyn MfaChallengeTokenGenerator> =
        Arc::new(OsMfaChallengeTokenGenerator);
    let challenge_hasher: Arc<dyn MfaChallengeTokenHasher> =
        Arc::new(Sha256MfaChallengeTokenHasher);
    let recovery_codes: Arc<dyn RecoveryCodeGenerator> = Arc::new(OsRecoveryCodeGenerator);
    let recovery_hasher: Arc<dyn RecoveryCodeHasher> =
        Arc::new(Argon2RecoveryCodeHasher::default());
    let mfa_clock: Arc<dyn MfaClock> = Arc::new(SystemMfaClock);
    let factor_verification = Arc::new(MfaFactorVerificationService::new(
        Arc::clone(&mfa_factors),
        Arc::clone(&totp_cipher),
        Arc::clone(&totp_verifier),
        Arc::clone(&recovery_hasher),
        Arc::clone(&mfa_clock),
    ));

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
    let user_profiles = SeaOrmUserProfileRepository::new(mysql.clone());
    let login_users = SeaOrmLoginUserRepository::new(mysql);
    let session_protection: Arc<dyn SessionProtectionPolicy> =
        Arc::new(MfaSessionProtectionPolicy::new(Arc::clone(&mfa_factors)));
    let authenticator = JwtAuthenticationService::with_protection_policy(
        verifier,
        sessions.clone(),
        authenticated_users.clone(),
        session_protection,
    );
    let get_user_service = GetUserService::new(user_profiles);
    let session_issuer = AuthenticatedSessionIssuer::new(
        sessions.clone(),
        UuidSessionIdGenerator,
        issuer,
        config.jwt.issuer.clone(),
        config.jwt.audience.clone(),
        config.jwt.ttl_seconds,
    )?;
    let mfa_login_service = MfaLoginService::new(
        LegacyMd5Verifier,
        login_users,
        authenticated_users.clone(),
        session_issuer,
        Arc::clone(&mfa_factors),
        Arc::clone(&mfa_challenges),
        challenge_tokens,
        challenge_hasher,
        Arc::clone(&factor_verification),
        Arc::clone(&mfa_clock),
        config.mfa.challenge_ttl_seconds,
        config.mfa.max_verification_attempts,
    )?;
    let mfa_management_service = MfaManagementService::new(
        mfa_factors,
        totp_secret_generator,
        totp_cipher,
        totp_verifier,
        recovery_codes,
        recovery_hasher,
        mfa_clock,
        config.mfa.issuer,
        config.mfa.enrollment_ttl_seconds,
        config.mfa.totp_period_seconds,
        config.mfa.totp_digits,
    )?;
    let state = AppState::new(
        authenticator,
        mfa_login_service,
        mfa_management_service,
        get_user_service,
        registry_port,
        runtime_state_reader,
        lifecycle_operation_service,
        configurator_directory,
        maps_file_service,
        maps_upload_limits,
        backup_lifecycle_service,
    );

    let openapi = base_openapi_document();

    let (router, openapi) = OpenApiRouter::<AppState>::with_openapi(openapi)
        .merge(server_instances::presentation::router::<AppState>())
        .nest("/auth", auth::presentation::mfa_router::<AppState>())
        .nest("/maps", maps::presentation::router::<AppState>())
        .nest("/backups", backups::presentation::router::<AppState>())
        .nest("/user", user::presentation::router::<AppState>())
        .with_state(state)
        .split_for_parts();

    Ok(BuiltApplication {
        router: router.merge(auth::presentation::openapi_router(openapi)),
        maintenance_worker,
        systemd_observer,
    })
}

fn base_openapi_document() -> utoipa::openapi::OpenApi {
    auth::presentation::openapi_document()
        .merge_from(maps::presentation::openapi_document())
        .merge_from(backups::presentation::openapi_document())
        .merge_from(server_instances::presentation::openapi_document())
        .merge_from(user::presentation::openapi_document())
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
            application::{
                authenticate_jwt::AuthenticateBearerToken,
                mfa::{login::MfaLogin, management::ManageMfa},
            },
            presentation::{extractors::JwtExtractorState, state::MfaState},
        },
        backups::{
            application::lifecycle::BackupLifecycleService, presentation::state::BackupsState,
        },
        maps::{application::file_service::MapsFileService, presentation::state::MapsState},
        server_instances::{
            application::{
                lifecycle_service::LifecycleOperationService, registry::InstanceRegistry,
                runtime_state::RuntimeStateReader,
            },
            presentation::state::ServerInstancesState,
        },
        shared::file_storage::upload::MultipartUploadLimits,
        user::{application::get_user::GetUser, presentation::state::UserState},
    };

    #[derive(Clone)]
    struct DocumentationState;

    impl JwtExtractorState for DocumentationState {
        fn jwt_authenticator(&self) -> Arc<dyn AuthenticateBearerToken> {
            panic!("documentation generation does not resolve authentication")
        }
    }

    impl MfaState for DocumentationState {
        fn mfa_login_service(&self) -> Arc<dyn MfaLogin> {
            panic!("documentation generation does not resolve application services")
        }

        fn mfa_management_service(&self) -> Arc<dyn ManageMfa> {
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

    impl UserState for DocumentationState {
        fn get_user_service(&self) -> Arc<dyn GetUser> {
            panic!("documentation generation does not resolve application services")
        }
    }

    impl ServerInstancesState for DocumentationState {
        fn instance_registry(&self) -> Arc<dyn InstanceRegistry> {
            panic!("documentation generation does not resolve application ports")
        }

        fn runtime_state_reader(&self) -> Arc<dyn RuntimeStateReader> {
            panic!("documentation generation does not resolve application ports")
        }

        fn lifecycle_operation_service(&self) -> Arc<LifecycleOperationService> {
            panic!("documentation generation does not resolve application services")
        }
    }

    #[test]
    fn global_openapi_document_contains_domain_routes() {
        let document = OpenApiRouter::<DocumentationState>::with_openapi(base_openapi_document())
            .merge(crate::server_instances::presentation::router())
            .nest("/auth", auth::presentation::mfa_router())
            .nest("/maps", maps::presentation::router())
            .nest("/backups", backups::presentation::router())
            .nest("/user", user::presentation::router())
            .into_openapi();
        let specification = serde_json::to_value(document).unwrap();

        assert_eq!(specification["openapi"], "3.1.0");
        assert!(specification["paths"]["/auth/login"]["post"].is_object());
        assert!(specification["paths"]["/auth/session"]["get"].is_object());
        assert!(specification["paths"]["/auth/login/mfa"]["post"].is_object());
        assert!(specification["paths"]["/auth/mfa"]["get"].is_object());
        assert!(specification["paths"]["/auth/mfa/totp"]["delete"].is_object());
        assert!(specification["paths"]["/maps/tree"]["get"].is_object());
        assert!(specification["paths"]["/maps/files"]["post"].is_object());
        assert!(specification["paths"]["/backups/list"]["get"].is_object());
        assert!(specification["paths"]["/backups/backup/{backup_id}"]["get"].is_object());
        assert!(specification["paths"]["/backups/restore/{backup_id}"]["post"].is_object());
        assert!(specification["paths"]["/user/{id}"]["get"].is_object());
        assert!(specification["paths"]["/server-instances"]["get"].is_object());
        assert!(specification["paths"]["/server-instances/{instance_id}/state"]["get"].is_object());
        assert!(specification["components"]["schemas"]["UserResponse"].is_object());
        assert!(specification["components"]["schemas"]["MapFileMutationsResponse"].is_object());
        assert_eq!(
            specification["components"]["securitySchemes"]["bearerAuth"]["scheme"],
            "bearer"
        );
    }
}
