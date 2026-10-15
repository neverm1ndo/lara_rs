use chrono::{DateTime, Utc};

use super::{
    guard::BackupReceipt,
    mutation::{FileMutationKind, FileRevision, MutationActor, MutationId, StorageNamespace},
    path::RelativeStoragePath,
};

/// Fact emitted by the storage coordinator after a filesystem mutation has
/// completed successfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChanged {
    mutation_id: MutationId,
    namespace: StorageNamespace,
    actor: MutationActor,
    occurred_at: DateTime<Utc>,
    kind: FileMutationKind,
    source: Option<RelativeStoragePath>,
    destination: Option<RelativeStoragePath>,
    previous_revision: Option<FileRevision>,
    current_revision: Option<FileRevision>,
    backup_receipt: Option<BackupReceipt>,
}

impl FileChanged {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        mutation_id: MutationId,
        namespace: StorageNamespace,
        actor: MutationActor,
        occurred_at: DateTime<Utc>,
        kind: FileMutationKind,
        source: Option<RelativeStoragePath>,
        destination: Option<RelativeStoragePath>,
        previous_revision: Option<FileRevision>,
        current_revision: Option<FileRevision>,
        backup_receipt: Option<BackupReceipt>,
    ) -> Self {
        Self {
            mutation_id,
            namespace,
            actor,
            occurred_at,
            kind,
            source,
            destination,
            previous_revision,
            current_revision,
            backup_receipt,
        }
    }

    pub fn mutation_id(&self) -> MutationId {
        self.mutation_id
    }

    pub fn namespace(&self) -> &StorageNamespace {
        &self.namespace
    }

    pub fn actor(&self) -> &MutationActor {
        &self.actor
    }

    pub fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }

    pub fn kind(&self) -> FileMutationKind {
        self.kind
    }

    pub fn source(&self) -> Option<&RelativeStoragePath> {
        self.source.as_ref()
    }

    pub fn destination(&self) -> Option<&RelativeStoragePath> {
        self.destination.as_ref()
    }

    pub fn previous_revision(&self) -> Option<&FileRevision> {
        self.previous_revision.as_ref()
    }

    pub fn current_revision(&self) -> Option<&FileRevision> {
        self.current_revision.as_ref()
    }

    pub fn backup_receipt(&self) -> Option<&BackupReceipt> {
        self.backup_receipt.as_ref()
    }
}
