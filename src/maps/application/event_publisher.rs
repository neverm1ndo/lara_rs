use std::{future::Future, pin::Pin};

use thiserror::Error;

use crate::maps::domain::MapsDomainEvent;

pub type PublishMapsEventFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), PublishMapsEventError>> + Send + 'a>>;

/// Application port for durable delivery of maps domain events.
///
/// A future infrastructure implementation may use an outbox. Implementations
/// must be idempotent by [`MapsDomainEvent::event_id`].
pub trait MapsEventPublisher: Send + Sync {
    fn publish<'a>(&'a self, event: &'a MapsDomainEvent) -> PublishMapsEventFuture<'a>;
}

#[derive(Debug, Error)]
#[error("failed to publish maps domain event: {message}")]
pub struct PublishMapsEventError {
    message: String,
}

impl PublishMapsEventError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publisher_error_keeps_a_non_empty_diagnostic_message() {
        let error = PublishMapsEventError::new("outbox unavailable");

        assert_eq!(error.message(), "outbox unavailable");
        assert!(error.to_string().contains("outbox unavailable"));
    }
}
