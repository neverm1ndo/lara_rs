use std::{sync::Arc, time::Duration};

use chrono::{Duration as ChronoDuration, Utc};
use thiserror::Error;
use tokio::sync::watch;
use tracing::{info, warn};
use uuid::Uuid;

use crate::server_instances::application::lifecycle_events::{
    LifecycleEventDelivery, LifecycleEventOutbox, ServerInstanceEvent,
};

pub struct LifecycleEventDispatcher {
    outbox: Arc<dyn LifecycleEventOutbox>,
    delivery: Arc<dyn LifecycleEventDelivery>,
    interval: Duration,
    lease_duration: ChronoDuration,
    batch_size: usize,
}

impl LifecycleEventDispatcher {
    pub fn new(
        outbox: Arc<dyn LifecycleEventOutbox>,
        delivery: Arc<dyn LifecycleEventDelivery>,
        interval: Duration,
        lease_duration: Duration,
        batch_size: usize,
    ) -> Result<Self, InvalidLifecycleEventDispatcher> {
        let lease_duration = ChronoDuration::from_std(lease_duration)
            .map_err(|_| InvalidLifecycleEventDispatcher)?;
        if interval.is_zero() || lease_duration.is_zero() || batch_size == 0 {
            return Err(InvalidLifecycleEventDispatcher);
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
        info!("lifecycle event dispatcher started");
        let mut interval = tokio::time::interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = interval.tick() => self.dispatch_batch().await,
            }
        }
        info!("lifecycle event dispatcher stopped");
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
                    warn!(error = %error, "failed to claim lifecycle event");
                    break;
                }
            };

            if let Err(error) = self
                .delivery
                .deliver(&ServerInstanceEvent::OperationUpdated(claim.event.clone()))
                .await
            {
                warn!(
                    event_id = claim.event.event_id(),
                    error = %error,
                    "failed to deliver lifecycle event; lease will expire"
                );
                continue;
            }
            if let Err(error) = self.outbox.acknowledge(&claim).await {
                warn!(
                    event_id = claim.event.event_id(),
                    error = %error,
                    "delivered lifecycle event could not be acknowledged"
                );
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("lifecycle event dispatcher settings are invalid")]
pub struct InvalidLifecycleEventDispatcher;

#[cfg(test)]
mod tests {
    use std::{
        future,
        sync::{Arc, Mutex},
    };

    use chrono::Duration as ChronoDuration;

    use super::*;
    use crate::server_instances::{
        application::lifecycle_events::{
            ClaimedLifecycleEvent, LifecycleEventDeliveryError, LifecycleEventDeliveryFuture,
            LifecycleEventOutboxFuture, LifecycleOperationUpdatedEvent,
        },
        domain::{
            IdempotencyKey, LifecycleAction, LifecycleActorId, LifecycleOperation,
            LifecycleOperationEvidence, LifecycleOperationId, ObservationStatus, ProcessState,
            ReadinessStatus, RequestFingerprint, ServerInstanceId,
        },
    };

    #[derive(Default)]
    struct MemoryOutbox {
        claim: Mutex<Option<ClaimedLifecycleEvent>>,
        acknowledgements: Mutex<usize>,
    }

    impl LifecycleEventOutbox for MemoryOutbox {
        fn claim_next<'a>(
            &'a self,
            _now: chrono::DateTime<Utc>,
            _lease_until: chrono::DateTime<Utc>,
            _lease_token: &'a str,
        ) -> LifecycleEventOutboxFuture<'a, Option<ClaimedLifecycleEvent>> {
            Box::pin(future::ready(Ok(self.claim.lock().unwrap().take())))
        }

        fn acknowledge<'a>(
            &'a self,
            _claim: &'a ClaimedLifecycleEvent,
        ) -> LifecycleEventOutboxFuture<'a, ()> {
            *self.acknowledgements.lock().unwrap() += 1;
            Box::pin(future::ready(Ok(())))
        }
    }

    #[derive(Default)]
    struct MemoryDelivery(Mutex<Vec<String>>);

    impl LifecycleEventDelivery for MemoryDelivery {
        fn deliver<'a>(
            &'a self,
            event: &'a ServerInstanceEvent,
        ) -> LifecycleEventDeliveryFuture<'a> {
            self.0.lock().unwrap().push(event.name().to_owned());
            Box::pin(future::ready(Ok::<_, LifecycleEventDeliveryError>(())))
        }
    }

    fn event() -> LifecycleOperationUpdatedEvent {
        let now = Utc::now();
        let operation = LifecycleOperation::request(
            LifecycleOperationId::new(),
            ServerInstanceId::new("dev-dm").unwrap(),
            LifecycleAction::Start,
            LifecycleActorId::new(42).unwrap(),
            "neo",
            IdempotencyKey::new("request-1").unwrap(),
            RequestFingerprint::new("a".repeat(64)).unwrap(),
            LifecycleOperationEvidence::new(
                ProcessState::Inactive,
                ReadinessStatus::NotReady,
                ObservationStatus::Observed,
                Some(now),
                Some(0),
                None,
            ),
            now,
            now + ChronoDuration::minutes(2),
        )
        .unwrap();
        LifecycleOperationUpdatedEvent::from_operation(&operation)
    }

    #[tokio::test]
    async fn acknowledges_only_after_delivery() {
        let outbox = Arc::new(MemoryOutbox {
            claim: Mutex::new(Some(ClaimedLifecycleEvent {
                event: event(),
                lease_token: "lease".into(),
            })),
            ..Default::default()
        });
        let delivery = Arc::new(MemoryDelivery::default());
        let dispatcher = LifecycleEventDispatcher::new(
            outbox.clone(),
            delivery.clone(),
            Duration::from_secs(1),
            Duration::from_secs(30),
            10,
        )
        .unwrap();

        dispatcher.dispatch_batch().await;

        assert_eq!(*outbox.acknowledgements.lock().unwrap(), 1);
        assert_eq!(
            delivery.0.lock().unwrap().as_slice(),
            ["server_instance.operation.updated"]
        );
    }

    #[test]
    fn rejects_zero_settings() {
        let outbox = Arc::new(MemoryOutbox::default());
        let delivery = Arc::new(MemoryDelivery::default());
        assert!(
            LifecycleEventDispatcher::new(
                outbox,
                delivery,
                Duration::ZERO,
                Duration::from_secs(30),
                1,
            )
            .is_err()
        );
    }
}
