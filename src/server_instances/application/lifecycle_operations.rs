use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::server_instances::domain::{
    IdempotencyKey, LifecycleActorId, LifecycleOperation, LifecycleOperationId,
    LifecycleOperationVersion, ServerInstanceId,
};

pub type LifecycleOperationRepositoryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, LifecycleOperationRepositoryError>> + Send + 'a>>;

/// Durable operation store. Implementations must enforce both idempotency and
/// at most one non-terminal lifecycle operation per instance. `save` is an
/// optimistic compare-and-swap; a read followed by an unconditional write is
/// not a valid implementation.
pub trait LifecycleOperationRepository: Send + Sync {
    fn insert<'a>(
        &'a self,
        operation: &'a LifecycleOperation,
    ) -> LifecycleOperationRepositoryFuture<'a, ()>;

    fn find_by_id<'a>(
        &'a self,
        operation_id: LifecycleOperationId,
    ) -> LifecycleOperationRepositoryFuture<'a, Option<LifecycleOperation>>;

    fn find_by_idempotency_key<'a>(
        &'a self,
        actor_id: LifecycleActorId,
        idempotency_key: &'a IdempotencyKey,
    ) -> LifecycleOperationRepositoryFuture<'a, Option<LifecycleOperation>>;

    fn find_active_for_instance<'a>(
        &'a self,
        instance_id: &'a ServerInstanceId,
    ) -> LifecycleOperationRepositoryFuture<'a, Option<LifecycleOperation>>;

    fn list_for_instance<'a>(
        &'a self,
        instance_id: &'a ServerInstanceId,
        query: LifecycleOperationListQuery,
    ) -> LifecycleOperationRepositoryFuture<'a, Vec<LifecycleOperation>>;

    fn save<'a>(
        &'a self,
        operation: &'a LifecycleOperation,
        expected_version: LifecycleOperationVersion,
    ) -> LifecycleOperationRepositoryFuture<'a, ()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleOperationListCursor {
    pub created_at: DateTime<Utc>,
    pub operation_id: LifecycleOperationId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleOperationListQuery {
    pub cursor: Option<LifecycleOperationListCursor>,
    pub limit: usize,
}

impl LifecycleOperationListQuery {
    pub fn new(
        cursor: Option<LifecycleOperationListCursor>,
        limit: usize,
    ) -> Result<Self, InvalidLifecycleOperationQuery> {
        if limit == 0 {
            return Err(InvalidLifecycleOperationQuery);
        }
        Ok(Self { cursor, limit })
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum LifecycleOperationRepositoryError {
    #[error("lifecycle operation conflicts with an existing operation")]
    AlreadyExists,
    #[error("lifecycle operation was concurrently modified")]
    ConcurrentModification,
    #[error("persisted lifecycle operation is invalid: {message}")]
    InvalidData { message: String },
    #[error("lifecycle operation repository is unavailable: {message}")]
    Unavailable { message: String },
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("lifecycle operation page size must be greater than zero")]
pub struct InvalidLifecycleOperationQuery;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_cannot_be_empty() {
        assert_eq!(
            LifecycleOperationListQuery::new(None, 0),
            Err(InvalidLifecycleOperationQuery)
        );
        assert_eq!(
            LifecycleOperationListQuery::new(None, 25).unwrap().limit,
            25
        );
    }
}
