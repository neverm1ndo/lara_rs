mod app_state;
mod auth;
mod bootstrap;
// The configuration context is introduced layer by layer and will be wired
// into AppState when its application services and HTTP routes are ready.
#[allow(dead_code)]
mod configuration;
// The context also exposes event-publisher and backup integration contracts
// which intentionally remain unused until those adapters are introduced.
#[allow(dead_code)]
mod maps;
mod shared;
mod user;

use crate::shared::config::AppConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::try_init()?;
    let config = AppConfig::load()?;

    bootstrap::run(config).await
}
