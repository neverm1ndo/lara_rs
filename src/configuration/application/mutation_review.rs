use std::{future::Future, pin::Pin, sync::Arc};

use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::mutation_log::{
    ConfigurationFileEvidence, ConfigurationMutationLog, ConfigurationMutationRecord,
    ConfigurationMutationReview, ConfigurationMutationState, ConfigurationReviewAssessment,
};

pub type EvidenceFuture<'a> = Pin<Box<dyn Future<Output = ConfigurationFileEvidence> + Send + 'a>>;

pub trait ConfigurationEvidenceReader: Send + Sync {
    fn observe<'a>(&'a self, instance_id: &'a str, path: &'a str) -> EvidenceFuture<'a>;
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationMutationReviewSnapshot {
    pub record: ConfigurationMutationRecord,
    pub observed_source: ConfigurationFileEvidence,
    pub observed_destination: ConfigurationFileEvidence,
    pub evidence_token: String,
}

#[derive(Debug, Error)]
pub enum ConfigurationMutationReviewError {
    #[error("configuration mutation was not found")]
    NotFound,
    #[error("configuration mutation is not awaiting review")]
    InvalidState,
    #[error("review evidence has changed; inspect again")]
    EvidenceChanged,
    #[error("review requires a non-empty operator and reason")]
    InvalidReview,
    #[error("configuration mutation changed while review was being saved")]
    Conflict,
    #[error("configuration mutation review is unavailable")]
    Unavailable,
}

pub struct ConfigurationMutationReviewService {
    log: Arc<dyn ConfigurationMutationLog>,
    evidence: Arc<dyn ConfigurationEvidenceReader>,
}

impl ConfigurationMutationReviewService {
    pub fn new(
        log: Arc<dyn ConfigurationMutationLog>,
        evidence: Arc<dyn ConfigurationEvidenceReader>,
    ) -> Self {
        Self { log, evidence }
    }

    pub async fn inspect(
        &self,
        id: &str,
    ) -> Result<ConfigurationMutationReviewSnapshot, ConfigurationMutationReviewError> {
        let record = self
            .log
            .by_id(id)
            .await
            .map_err(|_| ConfigurationMutationReviewError::Unavailable)?
            .ok_or(ConfigurationMutationReviewError::NotFound)?;
        let observed_source = self.observe_path(&record, record.source.as_deref()).await;
        let observed_destination = self
            .observe_path(&record, record.destination.as_deref())
            .await;
        let evidence_token = evidence_token(&record, &observed_source, &observed_destination);
        Ok(ConfigurationMutationReviewSnapshot {
            record,
            observed_source,
            observed_destination,
            evidence_token,
        })
    }

    pub async fn resolve(
        &self,
        id: &str,
        reviewer: &str,
        reason: &str,
        assessment: ConfigurationReviewAssessment,
        expected_token: &str,
    ) -> Result<ConfigurationMutationReviewSnapshot, ConfigurationMutationReviewError> {
        if reviewer.trim().is_empty()
            || reason.trim().is_empty()
            || reviewer.len() > 128
            || reason.len() > 1024
            || reviewer.trim() != reviewer
            || reason.trim() != reason
            || reviewer.chars().any(char::is_control)
            || reason.chars().any(char::is_control)
        {
            return Err(ConfigurationMutationReviewError::InvalidReview);
        }
        let snapshot = self.inspect(id).await?;
        if snapshot.record.state != ConfigurationMutationState::ReconciliationRequired {
            return Err(ConfigurationMutationReviewError::InvalidState);
        }
        if snapshot.evidence_token != expected_token {
            return Err(ConfigurationMutationReviewError::EvidenceChanged);
        }
        let mut next = snapshot.record.clone();
        next.state = ConfigurationMutationState::Reviewed;
        next.active_path = None;
        next.updated_at = Utc::now().to_rfc3339();
        next.review = Some(ConfigurationMutationReview {
            reviewer: reviewer.to_owned(),
            reason: reason.to_owned(),
            assessment,
            observed_source: snapshot.observed_source.clone(),
            observed_destination: snapshot.observed_destination.clone(),
            evidence_token: expected_token.to_owned(),
            reviewed_at: next.updated_at.clone(),
        });
        if !self
            .log
            .transition(id, ConfigurationMutationState::ReconciliationRequired, next)
            .await
            .map_err(|_| ConfigurationMutationReviewError::Unavailable)?
        {
            return Err(ConfigurationMutationReviewError::Conflict);
        }
        self.inspect(id).await
    }

    async fn observe_path(
        &self,
        record: &ConfigurationMutationRecord,
        path: Option<&str>,
    ) -> ConfigurationFileEvidence {
        match path {
            Some(path) => self.evidence.observe(&record.instance_id, path).await,
            None => ConfigurationFileEvidence::NotApplicable,
        }
    }
}

fn evidence_token(
    record: &ConfigurationMutationRecord,
    source: &ConfigurationFileEvidence,
    destination: &ConfigurationFileEvidence,
) -> String {
    let bytes = serde_json::to_vec(&(
        record.id.as_str(),
        record.fingerprint.as_str(),
        record.source.as_deref(),
        record.destination.as_deref(),
        record.state,
        record.updated_at.as_str(),
        source,
        destination,
    ))
    .expect("review evidence is serializable");
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use super::*;
    use crate::configuration::application::mutation_log::MutationLogFuture;

    struct MemoryLog(Mutex<Option<ConfigurationMutationRecord>>);
    impl ConfigurationMutationLog for MemoryLog {
        fn reserve<'a>(&'a self, _: &'a ConfigurationMutationRecord) -> MutationLogFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
        fn by_key<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
        ) -> MutationLogFuture<'a, Option<ConfigurationMutationRecord>> {
            Box::pin(async { Ok(None) })
        }
        fn by_id<'a>(
            &'a self,
            id: &'a str,
        ) -> MutationLogFuture<'a, Option<ConfigurationMutationRecord>> {
            Box::pin(async move {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .as_ref()
                    .filter(|record| record.id == id)
                    .cloned())
            })
        }
        fn transition<'a>(
            &'a self,
            id: &'a str,
            from: ConfigurationMutationState,
            next: ConfigurationMutationRecord,
        ) -> MutationLogFuture<'a, bool> {
            Box::pin(async move {
                let mut record = self.0.lock().unwrap();
                if !record
                    .as_ref()
                    .is_some_and(|current| current.id == id && current.state == from)
                {
                    return Ok(false);
                }
                *record = Some(next);
                Ok(true)
            })
        }
        fn unresolved<'a>(&'a self) -> MutationLogFuture<'a, Vec<ConfigurationMutationRecord>> {
            Box::pin(async { Ok(vec![]) })
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

    struct MemoryEvidence(Mutex<HashMap<String, ConfigurationFileEvidence>>);
    impl ConfigurationEvidenceReader for MemoryEvidence {
        fn observe<'a>(&'a self, _: &'a str, path: &'a str) -> EvidenceFuture<'a> {
            Box::pin(async move {
                self.0
                    .lock()
                    .unwrap()
                    .get(path)
                    .cloned()
                    .unwrap_or(ConfigurationFileEvidence::Absent)
            })
        }
    }

    fn record() -> ConfigurationMutationRecord {
        ConfigurationMutationRecord {
            id: "mutation-1".into(),
            actor_user_id: "42".into(),
            idempotency_key: "key".into(),
            fingerprint: "fingerprint".into(),
            instance_id: "test".into(),
            operation: "overwrite".into(),
            source: Some("server.cfg".into()),
            destination: None,
            expected_hash: Some("\"sha256:before\"".into()),
            desired_hash: Some("sha256:after".into()),
            active_path: Some("test:server.cfg".into()),
            state: ConfigurationMutationState::ReconciliationRequired,
            created_at: "requested".into(),
            updated_at: "quarantined".into(),
            event: None,
            failure_code: None,
            delivered_at: None,
            delivery_lease_until: None,
            delivery_lease_token: None,
            review: None,
        }
    }

    #[tokio::test]
    async fn operator_review_requires_current_evidence_and_preserves_audit() {
        let log = Arc::new(MemoryLog(Mutex::new(Some(record()))));
        let evidence = Arc::new(MemoryEvidence(Mutex::new(HashMap::from([(
            "server.cfg".into(),
            ConfigurationFileEvidence::Hash("sha256:after".into()),
        )]))));
        let service = ConfigurationMutationReviewService::new(log.clone(), evidence.clone());
        let inspection = service.inspect("mutation-1").await.unwrap();
        evidence.0.lock().unwrap().insert(
            "server.cfg".into(),
            ConfigurationFileEvidence::Hash("sha256:changed".into()),
        );
        assert!(matches!(
            service
                .resolve(
                    "mutation-1",
                    "operator",
                    "checked logs",
                    ConfigurationReviewAssessment::Indeterminate,
                    &inspection.evidence_token
                )
                .await,
            Err(ConfigurationMutationReviewError::EvidenceChanged)
        ));
        assert_eq!(
            log.0.lock().unwrap().as_ref().unwrap().state,
            ConfigurationMutationState::ReconciliationRequired
        );
        let current = service.inspect("mutation-1").await.unwrap();
        let resolved = service
            .resolve(
                "mutation-1",
                "operator",
                "checked logs",
                ConfigurationReviewAssessment::Indeterminate,
                &current.evidence_token,
            )
            .await
            .unwrap();
        assert_eq!(resolved.record.state, ConfigurationMutationState::Reviewed);
        assert_eq!(resolved.record.active_path, None);
        assert_eq!(
            resolved.record.review.as_ref().unwrap().reviewer,
            "operator"
        );
        assert!(resolved.record.event.is_none());
        assert!(matches!(
            service
                .resolve(
                    "mutation-1",
                    "operator",
                    "again",
                    ConfigurationReviewAssessment::Indeterminate,
                    &current.evidence_token
                )
                .await,
            Err(ConfigurationMutationReviewError::InvalidState)
        ));
    }
}
