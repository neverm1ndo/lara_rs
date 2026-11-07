use std::{error::Error, sync::Arc, time::Duration};

use axum::Router;
use encoding_rs::Encoding;
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
    configuration::{
        application::{
            artifact_service::ConfigurationArtifactService,
            instance_text::InstanceConfigurationTextService,
            mutation_log::ConfigurationMutationLog, mutation_service::ConfigurationMutationService,
            target::ConfigurationTargetResolver,
        },
        domain::{BinaryExtension, ConfigurationFilePolicy},
        infrastructure::{
            artifact_service::LocalConfigurationArtifactService,
            event_dispatcher::ConfigurationEventDispatcher,
            file_service::LocalConfigurationFileService,
            instance_text::LocalInstanceConfigurationTextService,
            mutation_log::MongoConfigurationMutationLog,
        },
    },
    configuration_targets::ConfigurationTargetCatalog,
    maps::{
        self,
        domain::{MAPS_STORAGE_NAMESPACE, MapFilePolicy},
        infrastructure::file_service::LocalMapsFileService,
    },
    server_instances::{
        self,
        application::{
            incident_service::{
                IncidentObservation, IncidentObservationService, IncidentOperationLookup,
            },
            incidents::{IncidentCheckpointRepository, IncidentRepository},
            journal_replay::{IncidentReplay, JournalReader, JournalReplayService},
            lifecycle_events::{LifecycleEventDelivery, LifecycleEventOutbox},
            lifecycle_reconciliation::LifecycleReconciler,
            lifecycle_service::LifecycleOperationService,
            registry::InstanceRegistry,
            runtime_state::{RuntimeStateReader, RuntimeStateWriter},
        },
        domain::InstanceCapability,
        infrastructure::{
            config_registry::ConfiguredInstanceRegistry,
            incident_repository::MongoIncidentRepository,
            journal_reader::SystemJournalReader,
            lifecycle_event_dispatcher::LifecycleEventDispatcher,
            lifecycle_operation_repository::MongoLifecycleOperationRepository,
            lifecycle_operation_support::{
                SystemLifecycleOperationClock, UuidLifecycleOperationIdGenerator,
            },
            lifecycle_reconciliation_worker::LifecycleReconciliationWorker,
            runtime_state_store::InMemoryRuntimeStateStore,
            systemd_observer::{SystemdObservationTarget, SystemdObserverWorker},
            systemd_runtime::SystemdLifecycleRuntime,
        },
        presentation::realtime::configure_socket_io,
    },
    shared::{
        config::{AppConfig, model::BackupCompression},
        file_storage::{
            content::FileContentClassifier,
            local::{FileStorageLimits, LocalFileStorage},
            mutation::StorageNamespace,
            path::{RelativeStoragePath, StorageFileName},
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
const LIFECYCLE_RECONCILIATION_INTERVAL: Duration = Duration::from_secs(1);
const LIFECYCLE_EVENT_INTERVAL: Duration = Duration::from_millis(250);
const LIFECYCLE_EVENT_LEASE: Duration = Duration::from_secs(30);
const LIFECYCLE_EVENT_BATCH_SIZE: usize = 100;

pub async fn run(config: AppConfig) -> Result<(), BootstrapError> {
    let bind_address = config.server.bind_address;
    let application = build_application(config).await?;
    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let maintenance = tokio::spawn(application.maintenance_worker.run(shutdown_rx.clone()));
    let lifecycle_events = tokio::spawn(
        application
            .lifecycle_event_dispatcher
            .run(shutdown_rx.clone()),
    );
    let configuration_events = tokio::spawn(
        application
            .configuration_event_dispatcher
            .run(shutdown_rx.clone()),
    );
    let lifecycle_reconciliation = application
        .lifecycle_reconciliation
        .map(|worker| tokio::spawn(worker.run(shutdown_rx.clone())));
    let systemd_observer = application
        .systemd_observer
        .map(|worker| tokio::spawn(worker.run(shutdown_rx)));

    info!(address = %bind_address, "HTTP server listening");
    let server_result = axum::serve(listener, application.router)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    let _ = shutdown_tx.send(true);
    maintenance.await?;
    lifecycle_events.await?;
    configuration_events.await?;
    if let Some(observer) = systemd_observer {
        observer.await?;
    }
    if let Some(reconciliation) = lifecycle_reconciliation {
        reconciliation.await?;
    }
    server_result?;
    Ok(())
}

struct BuiltApplication {
    router: Router,
    maintenance_worker: BackupMaintenanceWorker,
    systemd_observer: Option<SystemdObserverWorker>,
    lifecycle_reconciliation: Option<LifecycleReconciliationWorker>,
    lifecycle_event_dispatcher: LifecycleEventDispatcher,
    configuration_event_dispatcher: ConfigurationEventDispatcher,
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
            .with_incident_tracking(
                descriptor.observability().incident_tracking()
                    && descriptor
                        .capabilities()
                        .contains(InstanceCapability::Incidents),
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
    let configuration_target_resolver: Arc<dyn ConfigurationTargetResolver> =
        Arc::new(ConfigurationTargetCatalog::open(&config, instance_registry.clone()).await?);
    let primary_configuration = match config
        .game_server
        .instances
        .iter()
        .find(|entry| entry.id == config.game_server.primary_instance)
    {
        Some(entry) => config
            .effective_configuration_policy(entry)?
            .expect("validated primary has configuration capability"),
        None => config.implicit_primary_configuration_policy()?,
    };
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
    let primary_id = instance_registry.primary().id().clone();
    let primary_storage_root = instance_registry
        .configured(&primary_id)
        .expect("validated registry always contains its primary")
        .storage_root();
    let game_server_storage = LocalFileStorage::open(primary_storage_root, storage_limits).await?;
    let maps_storage = game_server_storage.scoped(&maps_directory).await?;
    let configuration_encoding = Encoding::for_label(
        primary_configuration.fallback_encoding.as_bytes(),
    )
    .ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "configuration.files.fallback_encoding is not a recognized WHATWG label",
        )
    })?;
    let configuration_policy = ConfigurationFilePolicy::new(
        primary_configuration
            .binary_extensions
            .iter()
            .cloned()
            .map(BinaryExtension::new)
            .collect::<Result<Vec<_>, _>>()?,
        primary_configuration
            .binary_file_names
            .iter()
            .map(StorageFileName::new)
            .collect::<Result<Vec<_>, _>>()?,
        primary_configuration
            .ignored_paths
            .iter()
            .map(|path| RelativeStoragePath::try_from(path.as_path()))
            .collect::<Result<Vec<_>, _>>()?,
    )?;

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
    let incidents = Arc::new(MongoIncidentRepository::new(mongo_database.clone()));
    incidents.ensure_indexes().await?;
    let recovered_events = lifecycle_operations.recover_missing_events().await?;
    if recovered_events > 0 {
        info!(recovered_events, "recovered lifecycle outbox events");
    }
    let lifecycle_event_outbox: Arc<dyn LifecycleEventOutbox> = lifecycle_operations.clone();
    let lifecycle_runtime = Arc::new(SystemdLifecycleRuntime::from_registry(
        instance_registry.as_ref(),
    ));
    let registry_port: Arc<dyn InstanceRegistry> = instance_registry.clone();
    let incident_repository: Arc<dyn IncidentRepository> = incidents.clone();
    let incident_checkpoints: Arc<dyn IncidentCheckpointRepository> = incidents;
    let journal_reader: Arc<dyn JournalReader> = Arc::new(SystemJournalReader);
    let incident_replay: Arc<dyn IncidentReplay> = Arc::new(JournalReplayService::new(
        journal_reader,
        incident_repository.clone(),
        incident_checkpoints,
    ));
    let incident_operations: Arc<dyn IncidentOperationLookup> = lifecycle_operations.clone();
    let incident_observation: Arc<dyn IncidentObservation> =
        Arc::new(IncidentObservationService::new(
            registry_port.clone(),
            incident_repository,
            incident_operations,
        ));
    let lifecycle_operation_service = Arc::new(LifecycleOperationService::new(
        registry_port.clone(),
        lifecycle_operations,
        lifecycle_runtime,
        runtime_state_reader.clone(),
        Arc::new(SystemLifecycleOperationClock),
        Arc::new(UuidLifecycleOperationIdGenerator),
        LIFECYCLE_OPERATION_TIMEOUT,
    )?);
    let reconciliation_ids: Vec<_> = instance_registry
        .systemd_managed()
        .map(|configured| configured.descriptor().id().clone())
        .collect();
    let lifecycle_reconciliation = if reconciliation_ids.is_empty() {
        None
    } else {
        let reconciler: Arc<dyn LifecycleReconciler> = lifecycle_operation_service.clone();
        Some(LifecycleReconciliationWorker::new(
            reconciliation_ids,
            reconciler,
            LIFECYCLE_RECONCILIATION_INTERVAL,
        )?)
    };

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

    let backup_repository = Arc::new(MongoBackupRepository::new(mongo_database.clone()));
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
        &primary_configuration.fallback_encoding,
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
            primary_configuration.binary_extensions.clone(),
            primary_configuration.binary_file_names.clone(),
        )?,
        BackupPreparationPolicy::new(
            Duration::from_secs(config.backups.retention.lifetime_seconds),
            Duration::from_secs(config.backups.retention.stale_preparation_seconds),
            compression,
            config.backups.storage.compression_threshold_bytes,
        )?,
    ));
    let instance_text_service: Arc<dyn InstanceConfigurationTextService> = Arc::new(
        LocalInstanceConfigurationTextService::new(backup_provider.clone()),
    );
    let artifact_service: Arc<dyn ConfigurationArtifactService> = Arc::new(
        LocalConfigurationArtifactService::new(backup_provider.clone()),
    );
    let mutation_log = Arc::new(MongoConfigurationMutationLog::new(mongo_database));
    mutation_log.ensure_indexes().await?;
    let mutation_log_port: Arc<dyn ConfigurationMutationLog> = mutation_log;
    let configuration_mutation_service = Arc::new(ConfigurationMutationService::new(
        mutation_log_port.clone(),
        instance_text_service.clone(),
        artifact_service.clone(),
    ));
    let recovery = configuration_mutation_service
        .reconcile_unresolved()
        .await?;
    if recovery.resumable > 0 {
        info!(
            resumable = recovery.resumable,
            "configuration mutations can resume with their original keys"
        );
    }
    if recovery.review_required > 0 {
        tracing::warn!(
            review_required = recovery.review_required,
            "configuration mutations require review after restart"
        );
    }
    let configuration_file_service = LocalConfigurationFileService::new(
        game_server_storage.clone(),
        configuration_policy.clone(),
        backup_provider.clone(),
        configuration_encoding.name().to_ascii_lowercase(),
    );
    let maps_file_service =
        LocalMapsFileService::with_required_backups(maps_storage.clone(), backup_provider);

    let maps_namespace = StorageNamespace::new(MAPS_STORAGE_NAMESPACE)?;
    let configuration_namespace = StorageNamespace::new("configuration")?;
    let restore_target = Arc::new(
        CapabilityBackupRestoreTarget::new()
            .register(maps_namespace, maps_storage, |path| {
                MapFilePolicy.recognizes(path)
            })
            .register(configuration_namespace, game_server_storage, move |path| {
                !configuration_policy.is_ignored(path)
            }),
    );
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
    let authenticator: Arc<
        dyn crate::auth::application::authenticate_jwt::AuthenticateBearerToken,
    > = Arc::new(JwtAuthenticationService::with_protection_policy(
        verifier,
        sessions.clone(),
        authenticated_users.clone(),
        session_protection,
    ));
    let (socket_io_layer, socket_delivery, io) = configure_socket_io(authenticator.clone());
    let configuration_delivery = crate::configuration::presentation::realtime::configure(
        &io,
        authenticator.clone(),
        instance_registry.primary().id().to_string(),
        configurator_directory.clone(),
    );
    let configuration_event_dispatcher =
        ConfigurationEventDispatcher::new(mutation_log_port, configuration_delivery);
    let lifecycle_event_delivery: Arc<dyn LifecycleEventDelivery> = socket_delivery;
    let lifecycle_event_dispatcher = LifecycleEventDispatcher::new(
        lifecycle_event_outbox,
        lifecycle_event_delivery.clone(),
        LIFECYCLE_EVENT_INTERVAL,
        LIFECYCLE_EVENT_LEASE,
        LIFECYCLE_EVENT_BATCH_SIZE,
    )?;
    let systemd_observer = systemd_observer.map(|worker| {
        worker
            .with_event_delivery(lifecycle_event_delivery)
            .with_incident_observation(incident_observation)
            .with_journal_replay(incident_replay)
    });
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
        configuration_file_service,
        configuration_target_resolver,
        instance_text_service,
        artifact_service,
        configuration_mutation_service,
        configuration_encoding,
        storage_limits.max_stream_size_bytes,
        maps_file_service,
        maps_upload_limits,
        backup_lifecycle_service,
    );

    let openapi = base_openapi_document();

    let (router, openapi) = OpenApiRouter::<AppState>::with_openapi(openapi)
        .merge(server_instances::presentation::router::<AppState>())
        .merge(crate::configuration::presentation::instance_routes::router::<AppState>())
        .nest("/auth", auth::presentation::mfa_router::<AppState>())
        .nest("/maps", maps::presentation::router::<AppState>())
        .nest("/backups", backups::presentation::router::<AppState>())
        .nest("/user", user::presentation::router::<AppState>())
        .with_state(state)
        .split_for_parts();

    Ok(BuiltApplication {
        router: router
            .merge(auth::presentation::openapi_router(openapi))
            .layer(socket_io_layer),
        maintenance_worker,
        systemd_observer,
        lifecycle_reconciliation,
        lifecycle_event_dispatcher,
        configuration_event_dispatcher,
    })
}

fn base_openapi_document() -> utoipa::openapi::OpenApi {
    auth::presentation::openapi_document()
        .merge_from(crate::configuration::presentation::openapi_document())
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

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use serde_json::Value;
    use tower::ServiceExt;
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

    impl crate::configuration::presentation::instance_state::InstanceConfigurationState
        for DocumentationState
    {
        fn configuration_target_resolver(&self) -> Arc<dyn ConfigurationTargetResolver> {
            panic!("documentation only")
        }
        fn instance_text_service(&self) -> Arc<dyn InstanceConfigurationTextService> {
            panic!("documentation only")
        }
        fn artifact_service(&self) -> Arc<dyn ConfigurationArtifactService> {
            panic!("documentation only")
        }
        fn configuration_mutation_service(&self) -> Arc<ConfigurationMutationService> {
            panic!("documentation only")
        }
    }

    fn documented_routes() -> OpenApiRouter<DocumentationState> {
        OpenApiRouter::<DocumentationState>::with_openapi(base_openapi_document())
            .merge(crate::server_instances::presentation::router())
            .merge(crate::configuration::presentation::instance_routes::router())
            .nest("/auth", auth::presentation::mfa_router())
            .nest("/maps", maps::presentation::router())
            .nest("/backups", backups::presentation::router())
            .nest("/user", user::presentation::router())
    }

    #[test]
    fn global_openapi_document_contains_domain_routes_without_legacy_configuration() {
        let document = documented_routes().into_openapi();
        let specification = serde_json::to_value(document).unwrap();

        assert_eq!(specification["openapi"], "3.1.0");
        assert!(specification["paths"]["/auth/login"]["post"].is_object());
        assert!(specification["paths"]["/auth/session"]["get"].is_object());
        assert!(specification["paths"]["/auth/login/mfa"]["post"].is_object());
        assert!(specification["paths"]["/auth/mfa"]["get"].is_object());
        assert!(specification["paths"]["/auth/mfa/totp"]["delete"].is_object());
        assert!(specification["paths"]["/maps/tree"]["get"].is_object());
        assert!(specification["paths"]["/configuration/tree"].is_null());
        assert!(specification["paths"]["/configuration/files"].is_null());
        assert!(specification["paths"]["/configuration/files/rename"].is_null());
        assert!(
            specification["paths"]["/server-instances/{instance_id}/configuration/tree"]["get"]
                .is_object()
        );
        let base = "/server-instances/{instance_id}/configuration";
        for (suffix, methods) in [
            ("/files", &["get", "post", "put", "delete"][..]),
            ("/files/rename", &["patch"][..]),
            ("/artifacts", &["head", "put"][..]),
        ] {
            for method in methods {
                assert!(specification["paths"][format!("{base}{suffix}")][method].is_object());
            }
        }
        assert!(
            specification["paths"][format!("{base}/files")]["post"]["responses"]["201"].is_object()
        );
        assert!(
            specification["paths"][format!("{base}/files")]["put"]["responses"]["200"].is_object()
        );
        assert!(
            specification["paths"][format!("{base}/artifacts")]["put"]["responses"]["200"]
                .is_object()
        );
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

    #[tokio::test]
    async fn legacy_configuration_route_returns_not_found() {
        let (router, _) = documented_routes()
            .with_state(DocumentationState)
            .split_for_parts();
        for uri in [
            "/configuration/tree",
            "/configuration/files?path=server.cfg",
            "/configuration/files/rename",
        ] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        }
    }

    #[tokio::test]
    async fn instance_configuration_routes_require_a_session() {
        let (router, _) = documented_routes()
            .with_state(DocumentationState)
            .split_for_parts();
        for (method, uri) in [
            ("GET", "/server-instances/test/configuration/tree"),
            (
                "GET",
                "/server-instances/test/configuration/files?path=server.cfg",
            ),
            (
                "POST",
                "/server-instances/test/configuration/files?path=server.cfg",
            ),
            (
                "HEAD",
                "/server-instances/test/configuration/artifacts?path=mod.so",
            ),
            (
                "PUT",
                "/server-instances/test/configuration/artifacts?path=mod.so",
            ),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {uri}"
            );
        }
    }

    fn assert_contract_references_exist(document: &Value, node: &Value) {
        match node {
            Value::Object(fields) => {
                if let Some(reference) = fields.get("$ref").and_then(Value::as_str) {
                    let pointer = reference.strip_prefix('#').expect("local reference");
                    assert!(
                        document.pointer(pointer).is_some(),
                        "unresolved {reference}"
                    );
                }
                for value in fields.values() {
                    assert_contract_references_exist(document, value);
                }
            }
            Value::Array(items) => {
                for item in items {
                    assert_contract_references_exist(document, item);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn release_c_contract_freezes_scoped_paths_headers_and_errors() {
        let contract: Value = serde_json::from_str(include_str!(
            "../docs/api/release-c-configuration.openapi.json"
        ))
        .unwrap();
        assert_eq!(contract["openapi"], "3.1.0");
        assert_eq!(contract["security"][0]["bearerAuth"], serde_json::json!([]));
        assert_contract_references_exist(&contract, &contract);

        let paths = contract["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 4);
        assert!(
            paths
                .keys()
                .all(|path| path.starts_with("/server-instances/{instance_id}/configuration/"))
        );
        let tree = &contract["paths"]["/server-instances/{instance_id}/configuration/tree"];
        let files = &contract["paths"]["/server-instances/{instance_id}/configuration/files"];
        let rename =
            &contract["paths"]["/server-instances/{instance_id}/configuration/files/rename"];
        let artifacts =
            &contract["paths"]["/server-instances/{instance_id}/configuration/artifacts"];
        assert!(tree["get"].is_object());
        for method in ["get", "post", "put", "delete"] {
            assert!(files[method].is_object(), "missing files {method}");
        }
        assert!(rename["patch"].is_object());
        assert!(artifacts["head"].is_object());
        assert!(artifacts["put"].is_object());

        for operation in [
            &files["post"],
            &files["put"],
            &files["delete"],
            &rename["patch"],
            &artifacts["put"],
        ] {
            let parameters = operation["parameters"].as_array().unwrap();
            assert!(
                parameters
                    .iter()
                    .any(|parameter| parameter["$ref"] == "#/components/parameters/IdempotencyKey")
            );
            assert!(operation["responses"]["409"].is_object());
        }
        for operation in [
            &files["put"],
            &files["delete"],
            &rename["patch"],
            &artifacts["put"],
        ] {
            let parameters = operation["parameters"].as_array().unwrap();
            assert!(
                parameters
                    .iter()
                    .any(|parameter| parameter["$ref"] == "#/components/parameters/IfMatch")
            );
            assert!(operation["responses"]["412"].is_object());
            assert!(operation["responses"]["428"].is_object());
        }
        assert_eq!(
            files["get"]["responses"]["200"]["$ref"],
            "#/components/responses/TextFile"
        );
        assert_eq!(
            artifacts["head"]["responses"]["200"]["$ref"],
            "#/components/responses/ArtifactMetadata"
        );
        assert_eq!(
            artifacts["put"]["x-lara-roles"],
            serde_json::json!(["Developer"])
        );
        assert_eq!(
            artifacts["head"]["x-lara-roles"],
            serde_json::json!(["Developer"])
        );
        assert!(contract["paths"]["/configuration/files"].is_null());
    }
}
