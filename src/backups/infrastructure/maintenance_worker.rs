use std::{sync::Arc, time::Duration};

use thiserror::Error;
use tokio::{
    sync::watch,
    time::{MissedTickBehavior, interval},
};

use crate::backups::application::maintenance::BackupMaintenanceService;

/// Periodically runs bounded cleanup cycles until application shutdown.
/// MongoDB TTL is intentionally not used because snapshot deletion must be
/// coordinated with metadata state transitions.
pub struct BackupMaintenanceWorker {
    service: Arc<BackupMaintenanceService>,
    interval: Duration,
}

impl BackupMaintenanceWorker {
    pub fn new(
        service: Arc<BackupMaintenanceService>,
        interval: Duration,
    ) -> Result<Self, InvalidBackupMaintenanceWorker> {
        if interval.is_zero() {
            return Err(InvalidBackupMaintenanceWorker::Interval);
        }
        Ok(Self { service, interval })
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        if *shutdown.borrow() {
            return;
        }

        let mut timer = interval(self.interval);
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = timer.tick() => {
                    match self.service.run_once().await {
                        Ok(report) => tracing::info!(
                            expired_scanned = report.expired_scanned,
                            expired_deleted = report.expired_deleted,
                            stale_preparations_scanned = report.stale_preparations_scanned,
                            stale_preparations_failed = report.stale_preparations_failed,
                            stale_restores_released = report.stale_restores_released,
                            stale_deletions_completed = report.stale_deletions_completed,
                            conflicts = report.conflicts,
                            failures = report.failures,
                            "backup maintenance cycle completed"
                        ),
                        Err(error) => tracing::error!(
                            error = %error,
                            "backup maintenance cycle could not query metadata"
                        ),
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidBackupMaintenanceWorker {
    #[error("backup cleanup interval must be greater than zero")]
    Interval,
}
