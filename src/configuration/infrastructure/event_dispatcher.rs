use std::{sync::Arc, time::Duration};

use chrono::Utc;
use tokio::sync::watch;
use tracing::{info, warn};
use uuid::Uuid;

use crate::configuration::application::mutation_log::{
    ConfigurationEventDelivery, ConfigurationMutationLog,
};

pub struct ConfigurationEventDispatcher {
    log: Arc<dyn ConfigurationMutationLog>,
    delivery: Arc<dyn ConfigurationEventDelivery>,
}

impl ConfigurationEventDispatcher {
    pub fn new(
        log: Arc<dyn ConfigurationMutationLog>,
        delivery: Arc<dyn ConfigurationEventDelivery>,
    ) -> Self {
        Self { log, delivery }
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        info!("configuration event dispatcher started");
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = interval.tick() => self.dispatch_batch().await,
            }
        }
        info!("configuration event dispatcher stopped");
    }

    async fn dispatch_batch(&self) {
        for _ in 0..100 {
            let now = Utc::now();
            let now_text = now.to_rfc3339();
            let until = (now + chrono::Duration::seconds(30)).to_rfc3339();
            let token = Uuid::new_v4().to_string();
            let record = match self.log.claim_event(&token, &now_text, &until).await {
                Ok(Some(record)) => record,
                Ok(None) => break,
                Err(error) => {
                    warn!(%error, "configuration outbox claim failed");
                    break;
                }
            };
            let Some(event) = record.event.as_ref() else {
                warn!(mutation_id = %record.id, "claimed configuration mutation has no event");
                continue;
            };
            if let Err(error) = self.delivery.deliver(event).await {
                warn!(event_id = %event.event_id, %error, "configuration event delivery failed");
                continue;
            }
            if let Err(error) = self
                .log
                .acknowledge_event(&record.id, &token, &Utc::now().to_rfc3339())
                .await
            {
                warn!(event_id = %event.event_id, %error, "configuration event acknowledgement failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::configuration::application::mutation_log::{
        ConfigurationDeliveryFuture, ConfigurationMutationEvent, ConfigurationMutationRecord,
        ConfigurationMutationState, MutationLogFuture,
    };

    struct MemoryLog {
        record: Mutex<Option<ConfigurationMutationRecord>>,
        acknowledgements: Mutex<usize>,
    }

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
        fn transition<'a>(
            &'a self,
            _: &'a str,
            _: ConfigurationMutationState,
            _: ConfigurationMutationRecord,
        ) -> MutationLogFuture<'a, bool> {
            Box::pin(async { Ok(false) })
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
            Box::pin(async move { Ok(self.record.lock().unwrap().take()) })
        }
        fn acknowledge_event<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
            _: &'a str,
        ) -> MutationLogFuture<'a, ()> {
            Box::pin(async move {
                *self.acknowledgements.lock().unwrap() += 1;
                Ok(())
            })
        }
    }

    struct Delivery {
        fail: bool,
        count: Mutex<usize>,
    }
    impl ConfigurationEventDelivery for Delivery {
        fn deliver<'a>(
            &'a self,
            _: &'a ConfigurationMutationEvent,
        ) -> ConfigurationDeliveryFuture<'a> {
            Box::pin(async move {
                *self.count.lock().unwrap() += 1;
                if self.fail {
                    Err("disconnected".into())
                } else {
                    Ok(())
                }
            })
        }
    }

    fn record() -> ConfigurationMutationRecord {
        ConfigurationMutationRecord {
            id: "id".into(),
            actor_user_id: "42".into(),
            idempotency_key: "key".into(),
            fingerprint: "hash".into(),
            instance_id: "test".into(),
            operation: "create".into(),
            source: None,
            destination: Some("server.cfg".into()),
            expected_hash: None,
            desired_hash: None,
            active_path: None,
            state: ConfigurationMutationState::Succeeded,
            created_at: "now".into(),
            updated_at: "now".into(),
            event: Some(ConfigurationMutationEvent {
                event_id: "configuration.file-changed.v1:id".into(),
                mutation_id: "id".into(),
                instance_id: "test".into(),
                actor_user_id: "42".into(),
                actor_session_id: None,
                access_level: "developer".into(),
                operation: "create".into(),
                source: None,
                destination: Some("server.cfg".into()),
                previous_hash: None,
                current_hash: None,
                backup_id: None,
                occurred_at: "now".into(),
            }),
            failure_code: None,
            delivered_at: None,
            delivery_lease_until: None,
            delivery_lease_token: None,
        }
    }

    #[tokio::test]
    async fn acknowledges_only_after_successful_delivery() {
        for fail in [false, true] {
            let log = Arc::new(MemoryLog {
                record: Mutex::new(Some(record())),
                acknowledgements: Mutex::new(0),
            });
            let delivery = Arc::new(Delivery {
                fail,
                count: Mutex::new(0),
            });
            ConfigurationEventDispatcher::new(log.clone(), delivery.clone())
                .dispatch_batch()
                .await;
            assert_eq!(*delivery.count.lock().unwrap(), 1);
            assert_eq!(*log.acknowledgements.lock().unwrap(), usize::from(!fail));
        }
    }
}
