use std::{sync::Arc, time::Duration};

use chrono::{Duration as ChronoDuration, Utc};
use thiserror::Error;
use tokio::sync::watch;
use tracing::{info, warn};
use uuid::Uuid;

use crate::server_instances::application::incidents::{IncidentEventDelivery, IncidentOutbox};

pub struct IncidentEventDispatcher {
    outbox: Arc<dyn IncidentOutbox>,
    delivery: Arc<dyn IncidentEventDelivery>,
    interval: Duration,
    lease_duration: ChronoDuration,
    batch_size: usize,
}

impl IncidentEventDispatcher {
    pub fn new(
        outbox: Arc<dyn IncidentOutbox>,
        delivery: Arc<dyn IncidentEventDelivery>,
        interval: Duration,
        lease_duration: Duration,
        batch_size: usize,
    ) -> Result<Self, InvalidIncidentEventDispatcher> {
        let lease_duration =
            ChronoDuration::from_std(lease_duration).map_err(|_| InvalidIncidentEventDispatcher)?;
        if interval.is_zero() || lease_duration.is_zero() || batch_size == 0 {
            return Err(InvalidIncidentEventDispatcher);
        }
        Ok(Self {
            outbox,
            delivery,
            interval,
            lease_duration,
            batch_size,
        })
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        info!("incident event dispatcher started");
        let mut interval = tokio::time::interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = interval.tick() => self.dispatch_batch().await,
            }
        }
        info!("incident event dispatcher stopped");
    }

    async fn dispatch_batch(&self) {
        for _ in 0..self.batch_size {
            let now = Utc::now();
            let lease_until = now + self.lease_duration;
            let lease_token = Uuid::new_v4().to_string();
            let claim = match self.outbox.claim_next(now, lease_until, &lease_token).await {
                Ok(Some(claim)) => claim,
                Ok(None) => break,
                Err(error) => {
                    warn!(%error, "failed to claim incident event");
                    break;
                }
            };
            if let Err(error) = self.delivery.deliver(&claim.event).await {
                warn!(event_id = %claim.event.event_id, %error, "incident event delivery failed; lease will expire");
                continue;
            }
            if let Err(error) = self.outbox.acknowledge(&claim).await {
                warn!(event_id = %claim.event.event_id, %error, "delivered incident event could not be acknowledged");
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("incident event dispatcher settings are invalid")]
pub struct InvalidIncidentEventDispatcher;

#[cfg(test)]
mod tests {
    use std::{future, sync::Mutex};

    use super::*;
    use crate::server_instances::{
        application::incidents::{
            ClaimedIncidentEvent, IncidentDeliveryFuture, IncidentEventDeliveryError,
            IncidentOutboxEvent, IncidentStoreFuture,
        },
        domain::{
            IncidentId, IncidentKind, IncidentOperationalState, IncidentReviewState,
            ServerInstanceId,
        },
    };

    #[derive(Default)]
    struct MemoryOutbox {
        claims: Mutex<Vec<ClaimedIncidentEvent>>,
        acknowledged: Mutex<Vec<String>>,
    }

    impl IncidentOutbox for MemoryOutbox {
        fn claim_next<'a>(
            &'a self,
            _now: chrono::DateTime<Utc>,
            _until: chrono::DateTime<Utc>,
            _token: &'a str,
        ) -> IncidentStoreFuture<'a, Option<ClaimedIncidentEvent>> {
            Box::pin(future::ready(Ok(self.claims.lock().unwrap().pop())))
        }
        fn acknowledge<'a>(
            &'a self,
            claim: &'a ClaimedIncidentEvent,
        ) -> IncidentStoreFuture<'a, ()> {
            self.acknowledged
                .lock()
                .unwrap()
                .push(claim.event.event_id.clone());
            Box::pin(future::ready(Ok(())))
        }
    }

    #[derive(Default)]
    struct MemoryDelivery {
        fail_once: Mutex<bool>,
        delivered: Mutex<Vec<String>>,
    }

    impl IncidentEventDelivery for MemoryDelivery {
        fn deliver<'a>(&'a self, event: &'a IncidentOutboxEvent) -> IncidentDeliveryFuture<'a> {
            self.delivered.lock().unwrap().push(event.event_id.clone());
            let failed = std::mem::take(&mut *self.fail_once.lock().unwrap());
            Box::pin(future::ready(if failed {
                Err(IncidentEventDeliveryError::new("disconnected"))
            } else {
                Ok(())
            }))
        }
    }

    fn claim() -> ClaimedIncidentEvent {
        let now = Utc::now();
        let incident_id = IncidentId::new();
        ClaimedIncidentEvent {
            event: IncidentOutboxEvent {
                event_id: format!("incident:{incident_id}:0"),
                incident_id,
                instance_id: ServerInstanceId::new("test").unwrap(),
                version: 0,
                occurred_at: now,
                kind: IncidentKind::Outage,
                operational_state: IncidentOperationalState::Open,
                review_state: IncidentReviewState::Unreviewed,
                opened_at: now,
                recovered_at: None,
                actor_user_id: None,
            },
            lease_token: "lease".into(),
        }
    }

    #[tokio::test]
    async fn acknowledges_only_after_delivery_and_retries_with_same_event_id() {
        let first = claim();
        let outbox = Arc::new(MemoryOutbox {
            claims: Mutex::new(vec![first.clone()]),
            ..Default::default()
        });
        let delivery = Arc::new(MemoryDelivery {
            fail_once: Mutex::new(true),
            ..Default::default()
        });
        let dispatcher = IncidentEventDispatcher::new(
            outbox.clone(),
            delivery.clone(),
            Duration::from_secs(1),
            Duration::from_secs(30),
            10,
        )
        .unwrap();
        dispatcher.dispatch_batch().await;
        assert!(outbox.acknowledged.lock().unwrap().is_empty());
        // The Mongo outbox returns the same durable event after its lease
        // expires; this fake models that return without waiting thirty seconds.
        outbox.claims.lock().unwrap().push(first);
        dispatcher.dispatch_batch().await;
        assert_eq!(outbox.acknowledged.lock().unwrap().len(), 1);
        let delivered = delivery.delivered.lock().unwrap();
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0], delivered[1]);
    }

    #[test]
    fn rejects_invalid_dispatcher_settings() {
        let outbox = Arc::new(MemoryOutbox::default());
        let delivery = Arc::new(MemoryDelivery::default());
        assert!(
            IncidentEventDispatcher::new(
                outbox,
                delivery,
                Duration::ZERO,
                Duration::from_secs(30),
                1
            )
            .is_err()
        );
    }
}
