use crate::server_instances::domain::{ServerInstance, ServerInstanceId};

/// Read-only application port for the configured server-instance catalog.
pub trait InstanceRegistry: Send + Sync {
    fn primary(&self) -> ServerInstance;
    fn get(&self, id: &ServerInstanceId) -> Option<ServerInstance>;
    fn list(&self) -> Vec<ServerInstance>;
}
