use std::{collections::BTreeMap, sync::Arc};

use mongodb::Client;
use thiserror::Error;

use crate::{
    cli::{MutationAssessmentArg, MutationReviewCommand, MutationReviewConfigArgs, OutputFormat},
    configuration::{
        application::{
            mutation_log::{ConfigurationMutationLog, ConfigurationReviewAssessment},
            mutation_review::{
                ConfigurationMutationReviewError, ConfigurationMutationReviewService,
                ConfigurationMutationReviewSnapshot,
            },
        },
        infrastructure::{
            mutation_evidence::LocalConfigurationEvidenceReader,
            mutation_log::MongoConfigurationMutationLog,
        },
    },
    server_instances::application::registry::InstanceRegistry,
    server_instances::infrastructure::config_registry::{
        ConfiguredInstanceRegistry, InstanceRegistryError,
    },
    shared::{
        config::{AppConfig, ConfigError},
        file_storage::local::{FileStorageLimits, LocalFileStorageError},
    },
};

#[derive(Debug, Error)]
pub enum MutationReviewCliError {
    #[error("review resolution requires --yes after inspecting the mutation")]
    ConfirmationRequired,
    #[cfg(target_os = "linux")]
    #[error("mutation resolution must run as root")]
    RootRequired,
    #[error("cannot read Lara environment file: {0}")]
    Environment(String),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Registry(#[from] InstanceRegistryError),
    #[error(transparent)]
    Storage(#[from] LocalFileStorageError),
    #[error(transparent)]
    Mongo(#[from] mongodb::error::Error),
    #[error(transparent)]
    Review(#[from] ConfigurationMutationReviewError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub async fn execute(command: MutationReviewCommand) -> Result<(), MutationReviewCliError> {
    let config_args = match &command {
        MutationReviewCommand::Inspect(args) => &args.config,
        MutationReviewCommand::Resolve(args) => &args.config,
    };
    if let MutationReviewCommand::Resolve(args) = &command
        && !args.yes
    {
        return Err(MutationReviewCliError::ConfirmationRequired);
    }
    #[cfg(target_os = "linux")]
    if matches!(&command, MutationReviewCommand::Resolve(_)) && unsafe { libc::geteuid() } != 0 {
        return Err(MutationReviewCliError::RootRequired);
    }
    let service = connect(config_args).await?;
    let (snapshot, output) = match command {
        MutationReviewCommand::Inspect(args) => (
            service.inspect(&args.mutation_id).await?,
            args.config.output,
        ),
        MutationReviewCommand::Resolve(args) => (
            service
                .resolve(
                    &args.mutation_id,
                    &args.reviewer,
                    &args.reason,
                    args.assessment.into(),
                    &args.evidence_token,
                )
                .await?,
            args.config.output,
        ),
    };
    print_snapshot(&snapshot, output)?;
    Ok(())
}

async fn connect(
    args: &MutationReviewConfigArgs,
) -> Result<ConfigurationMutationReviewService, MutationReviewCliError> {
    let environment = dotenvy::from_path_iter(&args.environment_file)
        .map_err(|error| MutationReviewCliError::Environment(error.to_string()))?
        .map(|entry| entry.map_err(|error| MutationReviewCliError::Environment(error.to_string())))
        .collect::<Result<Vec<_>, _>>()?;
    let config = AppConfig::load_explicit(&args.overlay_file, environment)?;
    let registry = ConfiguredInstanceRegistry::from_config(&config.game_server)?;
    let roots: BTreeMap<String, _> = registry
        .list()
        .into_iter()
        .filter_map(|instance| {
            registry.configured(instance.id()).map(|configured| {
                (
                    instance.id().to_string(),
                    configured.storage_root().to_path_buf(),
                )
            })
        })
        .collect();
    let limits = FileStorageLimits::new(
        config.game_server.storage.max_tree_depth,
        config.game_server.storage.max_tree_entries,
        config.game_server.storage.max_stream_size_bytes,
    )?;
    let mongo = Client::with_uri_str(config.mongodb.uri.expose_secret()).await?;
    let log: Arc<dyn ConfigurationMutationLog> = Arc::new(MongoConfigurationMutationLog::new(
        mongo.database(&config.mongodb.database),
    ));
    Ok(ConfigurationMutationReviewService::new(
        log,
        Arc::new(LocalConfigurationEvidenceReader::new(roots, limits)),
    ))
}

fn print_snapshot(
    snapshot: &ConfigurationMutationReviewSnapshot,
    output: OutputFormat,
) -> Result<(), serde_json::Error> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(snapshot)?),
        OutputFormat::Human => {
            println!("mutation: {}", snapshot.record.id);
            println!("instance: {}", snapshot.record.instance_id);
            println!("state: {:?}", snapshot.record.state);
            println!("actor user ID: {}", snapshot.record.actor_user_id);
            println!("operation: {}", snapshot.record.operation);
            println!("created at: {}", snapshot.record.created_at);
            println!("updated at: {}", snapshot.record.updated_at);
            println!(
                "source: {:?} => {:?}",
                snapshot.record.source, snapshot.observed_source
            );
            println!(
                "destination: {:?} => {:?}",
                snapshot.record.destination, snapshot.observed_destination
            );
            println!("expected hash: {:?}", snapshot.record.expected_hash);
            println!("desired hash: {:?}", snapshot.record.desired_hash);
            println!("failure code: {:?}", snapshot.record.failure_code);
            println!("evidence token: {}", snapshot.evidence_token);
            if let Some(review) = &snapshot.record.review {
                println!(
                    "review: {:?} by {} at {} — {}",
                    review.assessment, review.reviewer, review.reviewed_at, review.reason
                );
            }
        }
    }
    Ok(())
}

impl From<MutationAssessmentArg> for ConfigurationReviewAssessment {
    fn from(value: MutationAssessmentArg) -> Self {
        match value {
            MutationAssessmentArg::Applied => Self::Applied,
            MutationAssessmentArg::NotApplied => Self::NotApplied,
            MutationAssessmentArg::Indeterminate => Self::Indeterminate,
        }
    }
}
