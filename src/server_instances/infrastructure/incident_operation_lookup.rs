use crate::server_instances::{
    application::{
        incident_service::{IncidentOperationFuture, IncidentOperationLookup},
        lifecycle_operations::{LifecycleOperationListQuery, LifecycleOperationRepository},
    },
    domain::ServerInstanceId,
    infrastructure::lifecycle_operation_repository::MongoLifecycleOperationRepository,
};

const CORRELATION_WINDOW_LIMIT: usize = 32;

impl IncidentOperationLookup for MongoLifecycleOperationRepository {
    fn recent<'a>(&'a self, instance_id: &'a ServerInstanceId) -> IncidentOperationFuture<'a> {
        Box::pin(async move {
            self.list_for_instance(
                instance_id,
                LifecycleOperationListQuery::new(None, CORRELATION_WINDOW_LIMIT)
                    .expect("correlation window limit is positive"),
            )
            .await
            .map_err(|error| error.to_string())
        })
    }
}
