use std::{future::Future, pin::Pin};

use thiserror::Error;

use crate::configuration::domain::ConfigurationDomainEvent;

pub type PublishConfigurationEventFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), PublishConfigurationEventError>> + Send + 'a>>;

/// Application port for durable delivery of configuration domain events.
/// Implementations may use an outbox and must support idempotency by event ID.
pub trait ConfigurationEventPublisher: Send + Sync {
    fn publish<'a>(
        &'a self,
        event: &'a ConfigurationDomainEvent,
    ) -> PublishConfigurationEventFuture<'a>;
}

#[derive(Debug, Error)]
#[error("failed to publish configuration domain event: {message}")]
pub struct PublishConfigurationEventError {
    message: String,
}

impl PublishConfigurationEventError {
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
        let error = PublishConfigurationEventError::new("outbox unavailable");

        assert_eq!(error.message(), "outbox unavailable");
        assert!(error.to_string().contains("outbox unavailable"));
    }
}
