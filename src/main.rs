mod admin_cli;
mod app_state;
mod auth;
// The backups context is introduced layer by layer. Its domain model is kept
// independent from MongoDB, the local filesystem and HTTP adapters.
#[allow(dead_code)]
mod backups;
mod bootstrap;
mod cli;
// The configuration context is introduced layer by layer and will be wired
// into AppState when its application services and HTTP routes are ready.
#[allow(dead_code)]
mod configuration;
// The context also exposes event-publisher and backup integration contracts
// which intentionally remain unused until those adapters are introduced.
#[allow(dead_code)]
mod maps;
#[allow(dead_code)]
mod server_instances;
mod shared;
mod user;

use clap::Parser;

use crate::{cli::Command, shared::config::AppConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = cli::Cli::parse();

    match cli.command {
        Command::Serve => serve().await,
        Command::Config { command } => admin_cli::config::execute(command).map_err(Into::into),
        Command::Instance { command } => admin_cli::instance::execute(command)
            .await
            .map_err(Into::into),
        Command::Doctor(args) => admin_cli::doctor::execute(args).await.map_err(Into::into),
        Command::Completions(args) => {
            admin_cli::completions::execute(args);
            Ok(())
        }
    }
}

async fn serve() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::try_init()?;
    let config = AppConfig::load()?;

    bootstrap::run(config).await
}
