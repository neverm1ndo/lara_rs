use std::{future::Future, pin::Pin};

use crate::server_instances::{
    application::lifecycle_service::{LifecycleOperationService, LifecycleOperationServiceError},
    domain::ServerInstanceId,
};

pub type LifecycleReconciliationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), LifecycleOperationServiceError>> + Send + 'a>>;

/// Narrow worker-facing port. It deliberately exposes neither command
/// dispatch nor repository access, so background recovery can only reconcile
/// the allowlisted instance it was assigned.
pub trait LifecycleReconciler: Send + Sync {
    fn reconcile_active<'a>(
        &'a self,
        instance_id: &'a ServerInstanceId,
    ) -> LifecycleReconciliationFuture<'a>;
}

impl LifecycleReconciler for LifecycleOperationService {
    fn reconcile_active<'a>(
        &'a self,
        instance_id: &'a ServerInstanceId,
    ) -> LifecycleReconciliationFuture<'a> {
        Box::pin(async move {
            self.recover_active(instance_id).await?;
            Ok(())
        })
    }
}
