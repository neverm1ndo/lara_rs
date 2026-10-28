use chrono::Utc;

use crate::server_instances::{
    application::lifecycle_operations::{LifecycleOperationClock, LifecycleOperationIdGenerator},
    domain::LifecycleOperationId,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemLifecycleOperationClock;

impl LifecycleOperationClock for SystemLifecycleOperationClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UuidLifecycleOperationIdGenerator;

impl LifecycleOperationIdGenerator for UuidLifecycleOperationIdGenerator {
    fn next_id(&self) -> LifecycleOperationId {
        LifecycleOperationId::new()
    }
}
