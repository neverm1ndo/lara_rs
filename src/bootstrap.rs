use std::{error::Error, sync::Arc};

use axum::Router;
use mongodb::Client;
use sea_orm::Database;
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
    maps::{self, infrastructure::file_service::LocalMapsFileService},
    shared::{
        config::AppConfig,
        file_storage::{
            guard::NoBackupProvider,
            local::{FileStorageLimits, LocalFileStorage},
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
    let app = build_router(config).await?;
    let listener = tokio::net::TcpListener::bind(bind_address).await?;

    info!(address = %bind_address, "HTTP server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn build_router(config: AppConfig) -> Result<Router, BootstrapError> {
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
    let maps_file_service = LocalMapsFileService::new(maps_storage, Arc::new(NoBackupProvider));

    let mysql = Database::connect(config.mysql.url.expose_secret()).await?;
    let mongo = Client::with_uri_str(config.mongodb.uri.expose_secret()).await?;
    let mongo_database = mongo.database(&config.mongodb.database);

    let sessions = MongoSessionRepository::new(mongo_database);
    sessions.ensure_indexes().await?;

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
    );

    let openapi = base_openapi_document();

    let (router, openapi) = OpenApiRouter::<AppState>::with_openapi(openapi)
        .nest("/auth", auth::presentation::router::<AppState>())
        .nest("/maps", maps::presentation::router::<AppState>())
        .with_state(state)
        .split_for_parts();

    Ok(router.merge(auth::presentation::openapi_router(openapi)))
}

fn base_openapi_document() -> utoipa::openapi::OpenApi {
    auth::presentation::openapi_document().merge_from(maps::presentation::openapi_document())
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

    #[test]
    fn global_openapi_document_contains_auth_and_maps_routes() {
        let document = OpenApiRouter::<DocumentationState>::with_openapi(base_openapi_document())
            .nest("/auth", auth::presentation::router())
            .nest("/maps", maps::presentation::router())
            .into_openapi();
        let specification = serde_json::to_value(document).unwrap();

        assert_eq!(specification["openapi"], "3.1.0");
        assert!(specification["paths"]["/auth/login"]["post"].is_object());
        assert!(specification["paths"]["/auth/session"]["get"].is_object());
        assert!(specification["paths"]["/maps/tree"]["get"].is_object());
        assert!(specification["paths"]["/maps/files"]["post"].is_object());
        assert!(specification["components"]["schemas"]["MapFileMutationsResponse"].is_object());
        assert_eq!(
            specification["components"]["securitySchemes"]["bearerAuth"]["scheme"],
            "bearer"
        );
    }
}
