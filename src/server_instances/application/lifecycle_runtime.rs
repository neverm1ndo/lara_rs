use std::{future::Future, pin::Pin};

use thiserror::Error;

use crate::server_instances::domain::{LifecycleAction, ServerInstanceId, SystemdJobReference};

pub type LifecycleRuntimeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<SystemdJobReference, LifecycleRuntimeError>> + Send + 'a>>;

/// Command-side process runtime. The caller supplies only a trusted instance
/// identifier and an action; unit names and executable paths never cross this
/// application boundary.
pub trait LifecycleRuntime: Send + Sync {
    fn dispatch<'a>(
        &'a self,
        instance_id: &'a ServerInstanceId,
        action: LifecycleAction,
    ) -> LifecycleRuntimeFuture<'a>;
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum LifecycleRuntimeError {
    #[error("server instance is not managed by the lifecycle runtime")]
    InstanceNotManaged,
    #[error("lifecycle runtime is unavailable: {message}")]
    Unavailable { message: String },
    #[error("lifecycle runtime rejected the command: {message}")]
    Rejected { message: String },
    #[error("lifecycle runtime returned an invalid job reference")]
    InvalidJobReference,
}
