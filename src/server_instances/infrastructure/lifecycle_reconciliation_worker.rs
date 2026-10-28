use std::{sync::Arc, time::Duration};

use thiserror::Error;
use tokio::{sync::watch, task::JoinSet};
use tracing::{debug, warn};

use crate::server_instances::{
    application::lifecycle_reconciliation::LifecycleReconciler, domain::ServerInstanceId,
};

pub struct LifecycleReconciliationWorker {
    instance_ids: Vec<ServerInstanceId>,
    reconciler: Arc<dyn LifecycleReconciler>,
    interval: Duration,
}

impl LifecycleReconciliationWorker {
    pub fn new(
        instance_ids: Vec<ServerInstanceId>,
        reconciler: Arc<dyn LifecycleReconciler>,
        interval: Duration,
    ) -> Result<Self, InvalidLifecycleReconciliationPolicy> {
        if interval.is_zero() {
            return Err(InvalidLifecycleReconciliationPolicy);
        }
        Ok(Self {
            instance_ids,
            reconciler,
            interval,
        })
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
                _ = ticker.tick() => self.reconcile_once().await,
            }
        }
    }

    async fn reconcile_once(&self) {
        let mut tasks = JoinSet::new();
        for instance_id in &self.instance_ids {
            let instance_id = instance_id.clone();
            let reconciler = Arc::clone(&self.reconciler);
            tasks.spawn(async move {
                let result = reconciler.reconcile_active(&instance_id).await;
                (instance_id, result)
            });
        }
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok((instance_id, Ok(()))) => {
                    debug!(%instance_id, "lifecycle operation reconciled");
                }
                Ok((instance_id, Err(error))) => {
                    warn!(%instance_id, %error, "lifecycle reconciliation failed");
                }
                Err(error) => {
                    warn!(%error, "lifecycle reconciliation task terminated unexpectedly");
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("lifecycle reconciliation interval must be greater than zero")]
pub struct InvalidLifecycleReconciliationPolicy;

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use crate::server_instances::application::{
        lifecycle_reconciliation::LifecycleReconciliationFuture,
        lifecycle_service::LifecycleOperationServiceError,
    };

    use super::*;

    #[derive(Default)]
    struct RecordingReconciler(Mutex<Vec<ServerInstanceId>>);

    impl LifecycleReconciler for RecordingReconciler {
        fn reconcile_active<'a>(
            &'a self,
            instance_id: &'a ServerInstanceId,
        ) -> LifecycleReconciliationFuture<'a> {
            Box::pin(async move {
                self.0.lock().unwrap().push(instance_id.clone());
                if instance_id.as_str() == "broken" {
                    Err(LifecycleOperationServiceError::InstanceNotFound)
                } else {
                    Ok(())
                }
            })
        }
    }

    #[test]
    fn rejects_a_busy_loop_policy() {
        assert!(
            LifecycleReconciliationWorker::new(
                Vec::new(),
                Arc::new(RecordingReconciler::default()),
                Duration::ZERO,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn one_failure_does_not_prevent_other_instances_from_reconciliation() {
        let reconciler = Arc::new(RecordingReconciler::default());
        let worker = LifecycleReconciliationWorker::new(
            vec![
                ServerInstanceId::new("first").unwrap(),
                ServerInstanceId::new("broken").unwrap(),
                ServerInstanceId::new("last").unwrap(),
            ],
            reconciler.clone(),
            Duration::from_secs(1),
        )
        .unwrap();

        worker.reconcile_once().await;

        let mut visited: Vec<_> = reconciler
            .0
            .lock()
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        visited.sort();
        assert_eq!(visited, ["broken", "first", "last"]);
    }
}
