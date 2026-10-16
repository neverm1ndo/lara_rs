mod model;

// Re-exported now as the public domain contract; adapters will consume these
// items as the next layers are introduced.
#[allow(unused_imports)]
pub use model::{
    Backup, BackupAction, BackupDiff, BackupDiffSkipReason, BackupId, BackupInitiatorId,
    BackupSnapshot, BackupSource, BackupState, InvalidBackup, SnapshotCompression,
};
