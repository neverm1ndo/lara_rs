use chrono::{DateTime, Utc};

use crate::backups::{
    application::ports::{BackupClock, BackupIdGenerator},
    domain::BackupId,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemBackupClock;

impl BackupClock for SystemBackupClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UuidBackupIdGenerator;

impl BackupIdGenerator for UuidBackupIdGenerator {
    fn next_id(&self) -> BackupId {
        BackupId::new()
    }
}
