use std::sync::Arc;

use chrono::Utc;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    configuration::{
        application::{
            artifact_service::{ConfigurationArtifactContent, ConfigurationArtifactService},
            instance_text::{
                ConfigurationEntityTag, InstanceConfigurationError, InstanceConfigurationMutation,
                InstanceConfigurationRequest, InstanceConfigurationTextService,
            },
            mutation_log::{
                ConfigurationMutationEvent, ConfigurationMutationLog,
                ConfigurationMutationLogError, ConfigurationMutationRecord,
                ConfigurationMutationState,
            },
        },
        domain::{ConfigurationAccessLevel, ConfigurationFileChange},
    },
    shared::file_storage::{mutation::MutationId, path::RelativeStoragePath},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationMutationKind {
    Create,
    Overwrite,
    Delete,
    Rename,
    ReplaceArtifact,
}

impl ConfigurationMutationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Overwrite => "overwrite",
            Self::Delete => "delete",
            Self::Rename => "rename",
            Self::ReplaceArtifact => "replace_artifact",
        }
    }
}

pub struct ConfigurationMutationCommand {
    pub kind: ConfigurationMutationKind,
    pub source: Option<RelativeStoragePath>,
    pub destination: Option<RelativeStoragePath>,
    pub expected: Option<ConfigurationEntityTag>,
    pub content: Option<Vec<u8>>,
    pub idempotency_key: String,
}

pub struct ConfigurationMutationResult {
    pub event: ConfigurationMutationEvent,
    pub replayed: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ConfigurationRecoverySummary {
    pub resumable: usize,
    pub review_required: usize,
}

#[derive(Debug, Error)]
pub enum ConfigurationMutationServiceError {
    #[error("idempotency key reused for a different request")]
    Conflict,
    #[error("mutation outcome requires reconciliation: {0}")]
    ReconciliationRequired(String),
    #[error("mutation was reviewed by an operator: {0}")]
    Reviewed(String),
    #[error("mutation log unavailable")]
    Unavailable,
    #[error(transparent)]
    Application(#[from] InstanceConfigurationError),
}

pub struct ConfigurationMutationService {
    log: Arc<dyn ConfigurationMutationLog>,
    text: Arc<dyn InstanceConfigurationTextService>,
    artifacts: Arc<dyn ConfigurationArtifactService>,
}

impl ConfigurationMutationService {
    pub fn new(
        log: Arc<dyn ConfigurationMutationLog>,
        text: Arc<dyn InstanceConfigurationTextService>,
        artifacts: Arc<dyn ConfigurationArtifactService>,
    ) -> Self {
        Self {
            log,
            text,
            artifacts,
        }
    }

    pub async fn execute(
        &self,
        context: InstanceConfigurationRequest,
        command: ConfigurationMutationCommand,
    ) -> Result<ConfigurationMutationResult, ConfigurationMutationServiceError> {
        let actor = context.actor().subject().to_owned();
        let source = command
            .source
            .as_ref()
            .map(|path| context.access().server_path(path).to_string());
        let destination = command
            .destination
            .as_ref()
            .map(|path| context.access().server_path(path).to_string());
        let expected_hash = command
            .expected
            .as_ref()
            .map(ConfigurationEntityTag::header_value);
        let desired_hash = command
            .content
            .as_ref()
            .map(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)));
        let fingerprint = fingerprint(
            command.kind,
            context.target().instance_id(),
            &source,
            &destination,
            &expected_hash,
            &desired_hash,
        );
        if let Some(existing) = self
            .log
            .by_key(&actor, &command.idempotency_key)
            .await
            .map_err(|_| ConfigurationMutationServiceError::Unavailable)?
        {
            if existing.fingerprint == fingerprint
                && existing.state == ConfigurationMutationState::Requested
            {
                return self.run_reserved(existing, context, command).await;
            }
            return replay(existing, &fingerprint);
        }

        let id = MutationId::new();
        let now = Utc::now().to_rfc3339();
        let active_path = source
            .as_ref()
            .or(destination.as_ref())
            .map(|path| format!("{}:{path}", context.target().instance_id()));
        let record = ConfigurationMutationRecord {
            id: id.to_string(),
            actor_user_id: actor.clone(),
            idempotency_key: command.idempotency_key.clone(),
            fingerprint: fingerprint.clone(),
            instance_id: context.target().instance_id().to_owned(),
            operation: command.kind.as_str().into(),
            source,
            destination,
            expected_hash,
            desired_hash,
            active_path,
            state: ConfigurationMutationState::Requested,
            created_at: now.clone(),
            updated_at: now,
            event: None,
            failure_code: None,
            delivered_at: None,
            delivery_lease_until: None,
            delivery_lease_token: None,
            review: None,
        };
        match self.log.reserve(&record).await {
            Ok(()) => {}
            Err(ConfigurationMutationLogError::AlreadyExists) => {
                if let Some(existing) = self
                    .log
                    .by_key(&actor, &command.idempotency_key)
                    .await
                    .map_err(|_| ConfigurationMutationServiceError::Unavailable)?
                {
                    if existing.fingerprint == fingerprint
                        && existing.state == ConfigurationMutationState::Requested
                    {
                        return self.run_reserved(existing, context, command).await;
                    }
                    return replay(existing, &fingerprint);
                }
                return Err(ConfigurationMutationServiceError::Conflict);
            }
            Err(_) => return Err(ConfigurationMutationServiceError::Unavailable),
        }

        self.run_reserved(record, context, command).await
    }

    async fn run_reserved(
        &self,
        mut record: ConfigurationMutationRecord,
        context: InstanceConfigurationRequest,
        command: ConfigurationMutationCommand,
    ) -> Result<ConfigurationMutationResult, ConfigurationMutationServiceError> {
        let id = MutationId::from_uuid(
            uuid::Uuid::parse_str(&record.id)
                .map_err(|_| ConfigurationMutationServiceError::Unavailable)?,
        );
        record.state = ConfigurationMutationState::Applying;
        record.updated_at = Utc::now().to_rfc3339();
        if !self
            .log
            .transition(
                &record.id,
                ConfigurationMutationState::Requested,
                record.clone(),
            )
            .await
            .map_err(|_| {
                ConfigurationMutationServiceError::ReconciliationRequired(record.id.clone())
            })?
        {
            return Err(ConfigurationMutationServiceError::ReconciliationRequired(
                record.id,
            ));
        }

        let applied = self.apply(context.with_mutation_id(id), command).await;
        match applied {
            Ok(applied) => {
                record.event = Some(event(&applied));
                record.state = ConfigurationMutationState::Succeeded;
                record.active_path = None;
                record.updated_at = Utc::now().to_rfc3339();
                if !self
                    .log
                    .transition(
                        &record.id,
                        ConfigurationMutationState::Applying,
                        record.clone(),
                    )
                    .await
                    .map_err(|_| {
                        ConfigurationMutationServiceError::ReconciliationRequired(record.id.clone())
                    })?
                {
                    return Err(ConfigurationMutationServiceError::ReconciliationRequired(
                        record.id,
                    ));
                }
                Ok(ConfigurationMutationResult {
                    event: record.event.expect("successful mutation has event"),
                    replayed: false,
                })
            }
            Err(error) => {
                if matches!(error, InstanceConfigurationError::Unavailable) {
                    record.state = ConfigurationMutationState::ReconciliationRequired;
                    record.updated_at = Utc::now().to_rfc3339();
                    let id = record.id.clone();
                    self.log
                        .transition(&id, ConfigurationMutationState::Applying, record)
                        .await
                        .map_err(|_| {
                            ConfigurationMutationServiceError::ReconciliationRequired(id.clone())
                        })?;
                    return Err(ConfigurationMutationServiceError::ReconciliationRequired(
                        id,
                    ));
                }
                record.failure_code = Some(application_error_code(&error).into());
                record.state = ConfigurationMutationState::Failed;
                record.active_path = None;
                record.updated_at = Utc::now().to_rfc3339();
                let id = record.id.clone();
                if !self
                    .log
                    .transition(&id, ConfigurationMutationState::Applying, record)
                    .await
                    .map_err(|_| {
                        ConfigurationMutationServiceError::ReconciliationRequired(id.clone())
                    })?
                {
                    return Err(ConfigurationMutationServiceError::ReconciliationRequired(
                        id,
                    ));
                }
                Err(error.into())
            }
        }
    }

    async fn apply(
        &self,
        context: InstanceConfigurationRequest,
        command: ConfigurationMutationCommand,
    ) -> Result<InstanceConfigurationMutation, InstanceConfigurationError> {
        let source = || {
            command
                .source
                .clone()
                .ok_or(InstanceConfigurationError::NotFound)
        };
        let destination = || {
            command
                .destination
                .clone()
                .ok_or(InstanceConfigurationError::NotFound)
        };
        let expected = || {
            command
                .expected
                .clone()
                .ok_or(InstanceConfigurationError::PreconditionFailed)
        };
        match command.kind {
            ConfigurationMutationKind::Create => {
                self.text
                    .create(
                        context.clone(),
                        destination()?,
                        context.validate_content(
                            command
                                .content
                                .ok_or(InstanceConfigurationError::InvalidEncoding)?,
                        )?,
                    )
                    .await
            }
            ConfigurationMutationKind::Overwrite => {
                self.text
                    .overwrite(
                        context.clone(),
                        source()?,
                        context.validate_content(
                            command
                                .content
                                .ok_or(InstanceConfigurationError::InvalidEncoding)?,
                        )?,
                        expected()?,
                    )
                    .await
            }
            ConfigurationMutationKind::Delete => {
                self.text.delete(context, source()?, expected()?).await
            }
            ConfigurationMutationKind::Rename => {
                self.text
                    .rename(context, source()?, destination()?, expected()?)
                    .await
            }
            ConfigurationMutationKind::ReplaceArtifact => {
                self.artifacts
                    .replace(
                        context,
                        source()?,
                        ConfigurationArtifactContent::new(
                            command
                                .content
                                .ok_or(InstanceConfigurationError::InvalidEncoding)?,
                        ),
                        expected()?,
                    )
                    .await
            }
        }
    }

    pub async fn reconcile_unresolved(
        &self,
    ) -> Result<ConfigurationRecoverySummary, ConfigurationMutationServiceError> {
        let records = self
            .log
            .unresolved()
            .await
            .map_err(|_| ConfigurationMutationServiceError::Unavailable)?;
        let mut summary = ConfigurationRecoverySummary::default();
        for mut record in records {
            let previous = record.state;
            if previous == ConfigurationMutationState::Requested {
                summary.resumable += 1;
                continue;
            }
            record.state = ConfigurationMutationState::ReconciliationRequired;
            record.updated_at = Utc::now().to_rfc3339();
            if self
                .log
                .transition(&record.id.clone(), previous, record)
                .await
                .map_err(|_| ConfigurationMutationServiceError::Unavailable)?
            {
                summary.review_required += 1;
            }
        }
        Ok(summary)
    }
}

fn replay(
    record: ConfigurationMutationRecord,
    fingerprint: &str,
) -> Result<ConfigurationMutationResult, ConfigurationMutationServiceError> {
    if record.fingerprint != fingerprint {
        return Err(ConfigurationMutationServiceError::Conflict);
    }
    match record.state {
        ConfigurationMutationState::Succeeded => record
            .event
            .map(|event| ConfigurationMutationResult {
                event,
                replayed: true,
            })
            .ok_or(ConfigurationMutationServiceError::Unavailable),
        ConfigurationMutationState::Failed => Err(ConfigurationMutationServiceError::Application(
            error_from_code(record.failure_code.as_deref()),
        )),
        ConfigurationMutationState::Reviewed => {
            Err(ConfigurationMutationServiceError::Reviewed(record.id))
        }
        _ => Err(ConfigurationMutationServiceError::ReconciliationRequired(
            record.id,
        )),
    }
}

fn fingerprint(
    kind: ConfigurationMutationKind,
    instance: &str,
    source: &Option<String>,
    destination: &Option<String>,
    expected: &Option<String>,
    desired: &Option<String>,
) -> String {
    let parts = serde_json::to_vec(&(
        kind.as_str(),
        instance,
        source,
        destination,
        expected,
        desired,
    ))
    .expect("serializable fingerprint");
    format!("{:x}", Sha256::digest(parts))
}

fn event(applied: &InstanceConfigurationMutation) -> ConfigurationMutationEvent {
    let changed = &applied.event;
    let operation = match changed.change() {
        ConfigurationFileChange::Created { .. } => "create",
        ConfigurationFileChange::Overwritten { .. } if applied.resource_kind == crate::configuration::application::instance_text::ConfigurationResourceKind::Artifact => "replace_artifact",
        ConfigurationFileChange::Overwritten { .. } => "overwrite",
        ConfigurationFileChange::Deleted { .. } => "delete",
        ConfigurationFileChange::Renamed { .. } => "rename",
    };
    let hash = |revision: Option<&crate::shared::file_storage::mutation::FileRevision>| {
        revision.and_then(|revision| revision.content_hash().map(ToString::to_string))
    };
    ConfigurationMutationEvent {
        event_id: changed.event_id().to_string(),
        mutation_id: changed.event_id().mutation_id().to_string(),
        instance_id: applied.instance_id.clone(),
        actor_user_id: changed.actor().subject().into(),
        actor_session_id: changed.actor().session().map(str::to_owned),
        access_level: match changed.access_level() {
            ConfigurationAccessLevel::Developer => "developer",
            ConfigurationAccessLevel::Configurator => "configurator",
        }
        .into(),
        operation: operation.into(),
        source: changed.change().source().map(ToString::to_string),
        destination: changed.change().destination().map(ToString::to_string),
        previous_hash: hash(changed.previous_revision()),
        current_hash: hash(changed.current_revision()),
        backup_id: changed
            .backup_receipt()
            .map(|receipt| receipt.backup_id().into()),
        occurred_at: changed.occurred_at().to_rfc3339(),
    }
}

fn application_error_code(error: &InstanceConfigurationError) -> &'static str {
    match error {
        InstanceConfigurationError::NotFound => "NOT_FOUND",
        InstanceConfigurationError::Forbidden => "FORBIDDEN",
        InstanceConfigurationError::AlreadyExists | InstanceConfigurationError::Conflict => {
            "CONFLICT"
        }
        InstanceConfigurationError::PreconditionFailed => "PRECONDITION_FAILED",
        InstanceConfigurationError::BinaryFile => "BINARY_FILE",
        InstanceConfigurationError::InvalidEncoding => "INVALID_ENCODING",
        InstanceConfigurationError::ContentTooLarge => "CONTENT_TOO_LARGE",
        InstanceConfigurationError::Unavailable => "SERVICE_UNAVAILABLE",
    }
}

fn error_from_code(code: Option<&str>) -> InstanceConfigurationError {
    match code {
        Some("NOT_FOUND") => InstanceConfigurationError::NotFound,
        Some("FORBIDDEN") => InstanceConfigurationError::Forbidden,
        Some("CONFLICT") => InstanceConfigurationError::Conflict,
        Some("PRECONDITION_FAILED") => InstanceConfigurationError::PreconditionFailed,
        Some("BINARY_FILE") => InstanceConfigurationError::BinaryFile,
        Some("INVALID_ENCODING") => InstanceConfigurationError::InvalidEncoding,
        Some("CONTENT_TOO_LARGE") => InstanceConfigurationError::ContentTooLarge,
        _ => InstanceConfigurationError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, path::PathBuf, sync::Mutex};

    use encoding_rs::UTF_8;
    use uuid::Uuid;

    use super::*;
    use crate::{
        configuration::{
            application::{
                mutation_log::MutationLogFuture,
                target::{
                    ConfigurationAccessScope, ConfigurationTarget, ConfigurationTargetError,
                    ConfigurationTargetResolver,
                },
            },
            domain::ConfigurationFilePolicy,
            infrastructure::{
                artifact_service::LocalConfigurationArtifactService,
                instance_text::LocalInstanceConfigurationTextService,
            },
        },
        shared::{
            file_storage::{
                guard::NoBackupProvider,
                local::{FileStorageLimits, LocalFileStorage},
                mutation::MutationActor,
            },
            user_role::UserRole,
        },
    };

    #[derive(Default)]
    struct MemoryLog(Mutex<HashMap<String, ConfigurationMutationRecord>>);

    impl ConfigurationMutationLog for MemoryLog {
        fn reserve<'a>(
            &'a self,
            record: &'a ConfigurationMutationRecord,
        ) -> MutationLogFuture<'a, ()> {
            Box::pin(async move {
                let mut records = self.0.lock().unwrap();
                if records.values().any(|item| {
                    item.actor_user_id == record.actor_user_id
                        && item.idempotency_key == record.idempotency_key
                }) {
                    return Err(ConfigurationMutationLogError::AlreadyExists);
                }
                records.insert(record.id.clone(), record.clone());
                Ok(())
            })
        }
        fn by_key<'a>(
            &'a self,
            actor: &'a str,
            key: &'a str,
        ) -> MutationLogFuture<'a, Option<ConfigurationMutationRecord>> {
            Box::pin(async move {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .values()
                    .find(|item| item.actor_user_id == actor && item.idempotency_key == key)
                    .cloned())
            })
        }
        fn by_id<'a>(
            &'a self,
            id: &'a str,
        ) -> MutationLogFuture<'a, Option<ConfigurationMutationRecord>> {
            Box::pin(async move { Ok(self.0.lock().unwrap().get(id).cloned()) })
        }
        fn transition<'a>(
            &'a self,
            id: &'a str,
            from: ConfigurationMutationState,
            next: ConfigurationMutationRecord,
        ) -> MutationLogFuture<'a, bool> {
            Box::pin(async move {
                let mut records = self.0.lock().unwrap();
                let Some(current) = records.get(id) else {
                    return Ok(false);
                };
                if current.state != from {
                    return Ok(false);
                }
                records.insert(id.into(), next);
                Ok(true)
            })
        }
        fn unresolved<'a>(&'a self) -> MutationLogFuture<'a, Vec<ConfigurationMutationRecord>> {
            Box::pin(async move {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|item| {
                        matches!(
                            item.state,
                            ConfigurationMutationState::Requested
                                | ConfigurationMutationState::Applying
                        )
                    })
                    .cloned()
                    .collect())
            })
        }
        fn claim_event<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
            _: &'a str,
        ) -> MutationLogFuture<'a, Option<ConfigurationMutationRecord>> {
            Box::pin(async { Ok(None) })
        }
        fn acknowledge_event<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
            _: &'a str,
        ) -> MutationLogFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    struct StaticResolver(Arc<ConfigurationTarget>);
    impl ConfigurationTargetResolver for StaticResolver {
        fn resolve(&self, id: &str) -> Result<Arc<ConfigurationTarget>, ConfigurationTargetError> {
            if id == "test" {
                Ok(self.0.clone())
            } else {
                Err(ConfigurationTargetError::NotFound)
            }
        }
    }

    struct TestRoot(PathBuf);
    impl Drop for TestRoot {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    async fn setup() -> (
        TestRoot,
        InstanceConfigurationRequest,
        ConfigurationMutationService,
        Arc<MemoryLog>,
    ) {
        let root =
            TestRoot(std::env::temp_dir().join(format!("lara-config-mutation-{}", Uuid::new_v4())));
        std::fs::create_dir(&root.0).unwrap();
        let storage =
            LocalFileStorage::open(&root.0, FileStorageLimits::new(8, 100, 1024).unwrap())
                .await
                .unwrap();
        let target = Arc::new(ConfigurationTarget::new(
            "test".into(),
            storage,
            ConfigurationFilePolicy::new([], [], []).unwrap(),
            UTF_8,
            vec![],
            ConfigurationAccessScope::Auxiliary,
        ));
        let resolver: Arc<dyn ConfigurationTargetResolver> = Arc::new(StaticResolver(target));
        let context = InstanceConfigurationRequest::authorize(
            resolver.as_ref(),
            "test",
            UserRole::Developer,
            &[],
            MutationActor::new("42", Some("session".into())).unwrap(),
        )
        .unwrap();
        let guard = Arc::new(NoBackupProvider);
        let log = Arc::new(MemoryLog::default());
        let service = ConfigurationMutationService::new(
            log.clone(),
            Arc::new(LocalInstanceConfigurationTextService::new(guard.clone())),
            Arc::new(LocalConfigurationArtifactService::new(guard)),
        );
        (root, context, service, log)
    }

    #[tokio::test]
    async fn durable_success_replays_without_touching_file_again() {
        let (root, context, service, log) = setup().await;
        let command = || ConfigurationMutationCommand {
            kind: ConfigurationMutationKind::Create,
            source: None,
            destination: Some(RelativeStoragePath::new("server.cfg").unwrap()),
            expected: None,
            content: Some(b"first".to_vec()),
            idempotency_key: "request-1".into(),
        };
        let first = service.execute(context.clone(), command()).await.unwrap();
        assert!(!first.replayed);
        assert_eq!(
            first.event.mutation_id,
            first.event.event_id.rsplit(':').next().unwrap()
        );
        let second = service.execute(context.clone(), command()).await.unwrap();
        assert!(second.replayed);
        assert_eq!(second.event, first.event);
        assert_eq!(std::fs::read(root.0.join("server.cfg")).unwrap(), b"first");
        assert_eq!(log.0.lock().unwrap().len(), 1);
        let changed = ConfigurationMutationCommand {
            content: Some(b"second".to_vec()),
            ..command()
        };
        assert!(matches!(
            service.execute(context, changed).await,
            Err(ConfigurationMutationServiceError::Conflict)
        ));
        assert_eq!(std::fs::read(root.0.join("server.cfg")).unwrap(), b"first");
    }

    #[tokio::test]
    async fn requested_intent_resumes_once_with_same_key_and_payload() {
        let (root, context, service, log) = setup().await;
        let id = MutationId::new().to_string();
        let destination = Some("server.cfg".to_owned());
        let desired = Some(format!("sha256:{:x}", Sha256::digest(b"first")));
        let record = ConfigurationMutationRecord {
            id: id.clone(),
            actor_user_id: "42".into(),
            idempotency_key: "request-1".into(),
            fingerprint: fingerprint(
                ConfigurationMutationKind::Create,
                "test",
                &None,
                &destination,
                &None,
                &desired,
            ),
            instance_id: "test".into(),
            operation: "create".into(),
            source: None,
            destination,
            expected_hash: None,
            desired_hash: desired,
            active_path: Some("test:server.cfg".into()),
            state: ConfigurationMutationState::Requested,
            created_at: "now".into(),
            updated_at: "now".into(),
            event: None,
            failure_code: None,
            delivered_at: None,
            delivery_lease_until: None,
            delivery_lease_token: None,
            review: None,
        };
        log.0.lock().unwrap().insert(id.clone(), record);
        assert_eq!(
            service.reconcile_unresolved().await.unwrap(),
            ConfigurationRecoverySummary {
                resumable: 1,
                review_required: 0
            }
        );
        let result = service
            .execute(
                context,
                ConfigurationMutationCommand {
                    kind: ConfigurationMutationKind::Create,
                    source: None,
                    destination: Some(RelativeStoragePath::new("server.cfg").unwrap()),
                    expected: None,
                    content: Some(b"first".to_vec()),
                    idempotency_key: "request-1".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(result.event.mutation_id, id);
        assert_eq!(std::fs::read(root.0.join("server.cfg")).unwrap(), b"first");
        assert_eq!(log.0.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn failed_mutation_replays_the_same_error_without_file_effect() {
        let (root, context, service, log) = setup().await;
        let command = || ConfigurationMutationCommand {
            kind: ConfigurationMutationKind::Create,
            source: None,
            destination: Some(RelativeStoragePath::new("bad.cfg").unwrap()),
            expected: None,
            content: Some(vec![0xff]),
            idempotency_key: "invalid-encoding".into(),
        };
        for _ in 0..2 {
            assert!(matches!(
                service.execute(context.clone(), command()).await,
                Err(ConfigurationMutationServiceError::Application(
                    InstanceConfigurationError::InvalidEncoding
                ))
            ));
        }
        assert!(!root.0.join("bad.cfg").exists());
        let records = log.0.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records.values().next().unwrap().state,
            ConfigurationMutationState::Failed
        );
    }

    #[tokio::test]
    async fn startup_quarantines_applying_intent_and_preserves_path_lock() {
        let (_, _, service, log) = setup().await;
        let record = ConfigurationMutationRecord {
            id: "id".into(),
            actor_user_id: "42".into(),
            idempotency_key: "key".into(),
            fingerprint: "hash".into(),
            instance_id: "test".into(),
            operation: "overwrite".into(),
            source: Some("server.cfg".into()),
            destination: None,
            expected_hash: None,
            desired_hash: None,
            active_path: Some("test:server.cfg".into()),
            state: ConfigurationMutationState::Applying,
            created_at: "now".into(),
            updated_at: "now".into(),
            event: None,
            failure_code: None,
            delivered_at: None,
            delivery_lease_until: None,
            delivery_lease_token: None,
            review: None,
        };
        log.0.lock().unwrap().insert(record.id.clone(), record);
        assert_eq!(
            service
                .reconcile_unresolved()
                .await
                .unwrap()
                .review_required,
            1
        );
        let saved = log.0.lock().unwrap().get("id").unwrap().clone();
        assert_eq!(
            saved.state,
            ConfigurationMutationState::ReconciliationRequired
        );
        assert_eq!(saved.active_path.as_deref(), Some("test:server.cfg"));
    }

    #[tokio::test]
    async fn startup_quarantines_applying_create_even_when_destination_is_absent() {
        let (_, _, service, log) = setup().await;
        let record = ConfigurationMutationRecord {
            id: MutationId::new().to_string(),
            actor_user_id: "42".into(),
            idempotency_key: "key".into(),
            fingerprint: "hash".into(),
            instance_id: "test".into(),
            operation: "create".into(),
            source: None,
            destination: Some("new.cfg".into()),
            expected_hash: None,
            desired_hash: Some("sha256:hash".into()),
            active_path: Some("test:new.cfg".into()),
            state: ConfigurationMutationState::Applying,
            created_at: "now".into(),
            updated_at: "now".into(),
            event: None,
            failure_code: None,
            delivered_at: None,
            delivery_lease_until: None,
            delivery_lease_token: None,
            review: None,
        };
        let id = record.id.clone();
        log.0.lock().unwrap().insert(id.clone(), record);
        assert_eq!(
            service
                .reconcile_unresolved()
                .await
                .unwrap()
                .review_required,
            1
        );
        let saved = log.0.lock().unwrap().get(&id).unwrap().clone();
        assert_eq!(
            saved.state,
            ConfigurationMutationState::ReconciliationRequired
        );
        assert_eq!(saved.active_path.as_deref(), Some("test:new.cfg"));
    }

    #[test]
    fn reviewed_mutation_cannot_be_replayed_as_a_success() {
        let record = ConfigurationMutationRecord {
            id: "reviewed-id".into(),
            actor_user_id: "42".into(),
            idempotency_key: "key".into(),
            fingerprint: "fingerprint".into(),
            instance_id: "test".into(),
            operation: "create".into(),
            source: None,
            destination: Some("server.cfg".into()),
            expected_hash: None,
            desired_hash: None,
            active_path: None,
            state: ConfigurationMutationState::Reviewed,
            created_at: "requested".into(),
            updated_at: "reviewed".into(),
            event: None,
            failure_code: None,
            delivered_at: None,
            delivery_lease_until: None,
            delivery_lease_token: None,
            review: None,
        };
        assert!(
            matches!(replay(record, "fingerprint"), Err(ConfigurationMutationServiceError::Reviewed(id)) if id == "reviewed-id")
        );
    }
}
