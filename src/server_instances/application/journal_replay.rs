use std::{future::Future, pin::Pin, sync::Arc};

use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use super::incidents::{
    IncidentCheckpointRepository, IncidentRepository, IncidentStoreError, JournalCheckpoint,
    JournalGap, JournalGapReason,
};
use crate::server_instances::domain::{
    Incident, IncidentChange, IncidentConfidence, IncidentEvidence, IncidentFactId, IncidentId,
    IncidentKind, IncidentUnitName, ProcessState, ServerInstanceId, TerminationEvidence,
    TerminationKind,
};

const PAGE_SIZE: usize = 256;
const UNIT_STARTED: &str = "39f53479d3a045ac8e11786248231fbf";
const UNIT_FAILURE_RESULT: &str = "d9b373ed55a64feb8242e02dbe79a49c";

#[derive(Debug, Clone)]
pub struct JournalEntry {
    pub boot_id: Uuid,
    pub cursor: String,
    pub occurred_at: DateTime<Utc>,
    pub message_id: Option<String>,
    pub result: Option<String>,
    pub invocation_id: Option<String>,
}

#[derive(Debug)]
pub struct JournalPage {
    pub entries: Vec<JournalEntry>,
    pub cursor_found: bool,
    pub persistent: bool,
}

pub type JournalReadFuture<'a> =
    Pin<Box<dyn Future<Output = Result<JournalPage, String>> + Send + 'a>>;

pub trait JournalReader: Send + Sync {
    fn read<'a>(
        &'a self,
        unit: &'a str,
        after: Option<&'a JournalCheckpoint>,
        limit: usize,
    ) -> JournalReadFuture<'a>;
}

pub type ReplayFuture<'a> =
    Pin<Box<dyn Future<Output = Result<bool, JournalReplayError>> + Send + 'a>>;

/// `true` means journald was available and is the authoritative incident
/// source for this refresh; the D-Bus classifier should not open a duplicate.
pub trait IncidentReplay: Send + Sync {
    fn replay<'a>(&'a self, instance: &'a ServerInstanceId, unit: &'a str) -> ReplayFuture<'a>;
}

pub struct JournalReplayService {
    reader: Arc<dyn JournalReader>,
    incidents: Arc<dyn IncidentRepository>,
    checkpoints: Arc<dyn IncidentCheckpointRepository>,
}

impl JournalReplayService {
    pub fn new(
        reader: Arc<dyn JournalReader>,
        incidents: Arc<dyn IncidentRepository>,
        checkpoints: Arc<dyn IncidentCheckpointRepository>,
    ) -> Self {
        Self {
            reader,
            incidents,
            checkpoints,
        }
    }

    async fn run(
        &self,
        instance: &ServerInstanceId,
        unit: &str,
    ) -> Result<bool, JournalReplayError> {
        let mut checkpoint = self.checkpoints.by_instance(instance).await?;
        loop {
            let page = match self.reader.read(unit, checkpoint.as_ref(), PAGE_SIZE).await {
                Ok(page) => page,
                Err(error) => {
                    self.gap(instance, checkpoint.as_ref(), JournalGapReason::ReadFailure)
                        .await?;
                    tracing::warn!(%instance, %unit, %error, "journal replay unavailable");
                    return Ok(false);
                }
            };
            if !page.persistent {
                self.gap(
                    instance,
                    checkpoint.as_ref(),
                    JournalGapReason::PersistentStorageMissing,
                )
                .await?;
                return Ok(false);
            }
            if checkpoint.is_some() && !page.cursor_found {
                self.gap(
                    instance,
                    checkpoint.as_ref(),
                    JournalGapReason::CursorExpired,
                )
                .await?;
            }
            let count = page.entries.len();
            for entry in page.entries {
                self.apply(instance, unit, &entry).await?;
                let next = JournalCheckpoint::new(
                    instance.clone(),
                    entry.boot_id,
                    entry.cursor,
                    checkpoint.as_ref().map_or(0, |old| old.version + 1),
                )?;
                self.checkpoints
                    .advance(&next, checkpoint.as_ref().map(|old| old.version))
                    .await?;
                checkpoint = Some(next);
            }
            if count < PAGE_SIZE {
                return Ok(true);
            }
        }
    }

    async fn gap(
        &self,
        instance: &ServerInstanceId,
        checkpoint: Option<&JournalCheckpoint>,
        reason: JournalGapReason,
    ) -> Result<(), JournalReplayError> {
        self.checkpoints
            .record_gap(&JournalGap {
                instance_id: instance.clone(),
                previous_cursor: checkpoint.map(|value| value.cursor.clone()),
                reason,
                detected_at: Utc::now(),
            })
            .await?;
        Ok(())
    }

    async fn apply(
        &self,
        instance: &ServerInstanceId,
        unit: &str,
        entry: &JournalEntry,
    ) -> Result<(), JournalReplayError> {
        let process = match entry.message_id.as_deref() {
            Some(UNIT_FAILURE_RESULT) => ProcessState::Failed,
            Some(UNIT_STARTED) => ProcessState::Active,
            _ => return Ok(()),
        };
        let fact = IncidentFactId::journal(entry.boot_id, entry.cursor.clone())?;
        if self
            .incidents
            .by_fact(instance, unit, &fact)
            .await?
            .is_some()
        {
            return Ok(());
        }
        let termination = if process == ProcessState::Failed {
            Some(TerminationEvidence::new(
                result_kind(entry.result.as_deref()),
                None,
            ))
        } else {
            None
        };
        let evidence = IncidentEvidence::new(
            fact,
            IncidentUnitName::new(unit)?,
            entry.occurred_at,
            process,
            entry.invocation_id.clone(),
            None,
            termination,
            IncidentConfidence::Confirmed,
        )?;
        if let Some(mut active) = self.incidents.active_for_instance(instance).await? {
            if process == ProcessState::Active && entry.occurred_at >= active.opened_at() {
                let expected = active.version();
                let at = entry.occurred_at.max(active.updated_at());
                if active.resolve(evidence, at)? == IncidentChange::Applied {
                    self.incidents.save(&active, expected).await?;
                }
            }
            return Ok(());
        }
        if process != ProcessState::Failed {
            return Ok(());
        }
        let incident = Incident::open(
            IncidentId::new(),
            instance.clone(),
            IncidentKind::Outage,
            evidence,
        )?;
        match self.incidents.insert(&incident).await {
            Ok(()) | Err(IncidentStoreError::FactConflict | IncidentStoreError::ActiveConflict) => {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl IncidentReplay for JournalReplayService {
    fn replay<'a>(&'a self, instance: &'a ServerInstanceId, unit: &'a str) -> ReplayFuture<'a> {
        Box::pin(self.run(instance, unit))
    }
}

fn result_kind(result: Option<&str>) -> TerminationKind {
    match result {
        Some("exit-code") => TerminationKind::ExitCode,
        Some("signal") => TerminationKind::Signal,
        Some("core-dump") => TerminationKind::CoreDump,
        Some("timeout") => TerminationKind::Timeout,
        Some("watchdog") => TerminationKind::Watchdog,
        Some("resources" | "oom-kill") => TerminationKind::ResourceFailure,
        Some("start-limit-hit") => TerminationKind::StartLimit,
        _ => TerminationKind::Unknown,
    }
}

#[derive(Debug, Error)]
pub enum JournalReplayError {
    #[error(transparent)]
    Store(#[from] IncidentStoreError),
    #[error(transparent)]
    Domain(#[from] crate::server_instances::domain::InvalidIncident),
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;
    use crate::server_instances::application::incidents::{IncidentStoreFuture, JournalGap};

    #[derive(Default)]
    struct Memory {
        incidents: Mutex<Vec<Incident>>,
        checkpoint: Mutex<Option<JournalCheckpoint>>,
        gaps: Mutex<Vec<JournalGap>>,
        fail_insert_once: AtomicBool,
    }

    impl IncidentRepository for Memory {
        fn insert<'a>(&'a self, incident: &'a Incident) -> IncidentStoreFuture<'a, ()> {
            Box::pin(async move {
                if self.fail_insert_once.swap(false, Ordering::SeqCst) {
                    return Err(IncidentStoreError::Unavailable(
                        "simulated write failure".into(),
                    ));
                }
                self.incidents.lock().unwrap().push(incident.clone());
                Ok(())
            })
        }
        fn by_id<'a>(&'a self, id: IncidentId) -> IncidentStoreFuture<'a, Option<Incident>> {
            Box::pin(async move {
                Ok(self
                    .incidents
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|item| item.id() == id)
                    .cloned())
            })
        }
        fn by_fact<'a>(
            &'a self,
            _: &'a ServerInstanceId,
            _: &'a str,
            fact: &'a IncidentFactId,
        ) -> IncidentStoreFuture<'a, Option<Incident>> {
            Box::pin(async move {
                Ok(self
                    .incidents
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|item| item.evidence().iter().any(|e| e.fact_id() == fact))
                    .cloned())
            })
        }
        fn active_for_instance<'a>(
            &'a self,
            instance: &'a ServerInstanceId,
        ) -> IncidentStoreFuture<'a, Option<Incident>> {
            Box::pin(async move {
                Ok(self.incidents.lock().unwrap().iter().find(|item| item.instance_id() == instance && item.operational_state() != crate::server_instances::domain::IncidentOperationalState::Resolved).cloned())
            })
        }
        fn save<'a>(&'a self, incident: &'a Incident, _: u64) -> IncidentStoreFuture<'a, ()> {
            Box::pin(async move {
                let mut all = self.incidents.lock().unwrap();
                let old = all
                    .iter_mut()
                    .find(|item| item.id() == incident.id())
                    .unwrap();
                *old = incident.clone();
                Ok(())
            })
        }
    }

    impl IncidentCheckpointRepository for Memory {
        fn by_instance<'a>(
            &'a self,
            _: &'a ServerInstanceId,
        ) -> IncidentStoreFuture<'a, Option<JournalCheckpoint>> {
            Box::pin(async move { Ok(self.checkpoint.lock().unwrap().clone()) })
        }
        fn advance<'a>(
            &'a self,
            checkpoint: &'a JournalCheckpoint,
            _: Option<u64>,
        ) -> IncidentStoreFuture<'a, ()> {
            Box::pin(async move {
                *self.checkpoint.lock().unwrap() = Some(checkpoint.clone());
                Ok(())
            })
        }
        fn record_gap<'a>(&'a self, gap: &'a JournalGap) -> IncidentStoreFuture<'a, ()> {
            Box::pin(async move {
                self.gaps.lock().unwrap().push(gap.clone());
                Ok(())
            })
        }
    }

    struct Reader {
        entries: Vec<JournalEntry>,
        missing_cursor: bool,
    }
    impl JournalReader for Reader {
        fn read<'a>(
            &'a self,
            _: &'a str,
            after: Option<&'a JournalCheckpoint>,
            limit: usize,
        ) -> JournalReadFuture<'a> {
            Box::pin(async move {
                let start = if self.missing_cursor {
                    0
                } else {
                    after
                        .and_then(|checkpoint| {
                            self.entries
                                .iter()
                                .position(|entry| entry.cursor == checkpoint.cursor)
                                .map(|position| position + 1)
                        })
                        .unwrap_or(0)
                };
                Ok(JournalPage {
                    entries: self.entries[start..].iter().take(limit).cloned().collect(),
                    cursor_found: after.is_none() || !self.missing_cursor,
                    persistent: true,
                })
            })
        }
    }

    #[tokio::test]
    async fn replays_failure_and_recovery_without_duplicate_after_restart() {
        let instance = ServerInstanceId::new("test").unwrap();
        let boot = Uuid::new_v4();
        let at = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let reader = Arc::new(Reader {
            missing_cursor: false,
            entries: vec![
                JournalEntry {
                    boot_id: boot,
                    cursor: "failure".into(),
                    occurred_at: at,
                    message_id: Some(UNIT_FAILURE_RESULT.into()),
                    result: Some("exit-code".into()),
                    invocation_id: None,
                },
                JournalEntry {
                    boot_id: boot,
                    cursor: "recovered".into(),
                    occurred_at: at + chrono::Duration::seconds(2),
                    message_id: Some(UNIT_STARTED.into()),
                    result: None,
                    invocation_id: None,
                },
            ],
        });
        let memory = Arc::new(Memory::default());
        let service = JournalReplayService::new(reader, memory.clone(), memory.clone());
        assert!(
            service
                .run(&instance, "lara-game@test.service")
                .await
                .unwrap()
        );
        assert!(
            service
                .run(&instance, "lara-game@test.service")
                .await
                .unwrap()
        );
        let incidents = memory.incidents.lock().unwrap();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].evidence().len(), 2);
        assert_eq!(
            incidents[0].recovered_at(),
            Some(at + chrono::Duration::seconds(2))
        );
        assert_eq!(
            memory.checkpoint.lock().unwrap().as_ref().unwrap().cursor,
            "recovered"
        );
    }

    #[tokio::test]
    async fn missing_cursor_records_gap_separately_from_incident() {
        let instance = ServerInstanceId::new("test").unwrap();
        let memory = Arc::new(Memory::default());
        *memory.checkpoint.lock().unwrap() =
            Some(JournalCheckpoint::new(instance.clone(), Uuid::new_v4(), "expired", 0).unwrap());
        let service = JournalReplayService::new(
            Arc::new(Reader {
                entries: vec![],
                missing_cursor: true,
            }),
            memory.clone(),
            memory.clone(),
        );
        assert!(
            service
                .run(&instance, "lara-game@test.service")
                .await
                .unwrap()
        );
        assert!(memory.incidents.lock().unwrap().is_empty());
        assert_eq!(
            memory.gaps.lock().unwrap()[0].reason,
            JournalGapReason::CursorExpired
        );
    }

    #[tokio::test]
    async fn failed_incident_write_does_not_advance_checkpoint() {
        let instance = ServerInstanceId::new("test").unwrap();
        let memory = Arc::new(Memory::default());
        memory.fail_insert_once.store(true, Ordering::SeqCst);
        let reader = Arc::new(Reader {
            missing_cursor: false,
            entries: vec![JournalEntry {
                boot_id: Uuid::new_v4(),
                cursor: "failure".into(),
                occurred_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                message_id: Some(UNIT_FAILURE_RESULT.into()),
                result: Some("signal".into()),
                invocation_id: None,
            }],
        });
        let service = JournalReplayService::new(reader, memory.clone(), memory.clone());
        assert!(
            service
                .run(&instance, "lara-game@test.service")
                .await
                .is_err()
        );
        assert!(memory.checkpoint.lock().unwrap().is_none());
        assert!(
            service
                .run(&instance, "lara-game@test.service")
                .await
                .unwrap()
        );
        assert_eq!(memory.incidents.lock().unwrap().len(), 1);
    }
}
