use std::error::Error;

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
    shared::{config::AppConfig, file_storage::path::RelativeStoragePath},
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
    let state = AppState::new(authenticator, login_service, configurator_directory);

    let (router, openapi) =
        OpenApiRouter::<AppState>::with_openapi(auth::presentation::openapi_document())
            .nest("/auth", auth::presentation::router::<AppState>())
            .with_state(state)
            .split_for_parts();

    Ok(router.merge(auth::presentation::openapi_router(openapi)))
}
