use std::sync::Arc;

use serde::{Deserialize, Serialize};
use socketioxide::{
    SocketIo,
    extract::{Data, SocketRef},
};

use crate::{
    auth::application::authenticate_jwt::AuthenticateBearerToken,
    configuration::application::mutation_log::{
        ConfigurationDeliveryFuture, ConfigurationEventDelivery, ConfigurationMutationEvent,
    },
    shared::{file_storage::path::RelativeStoragePath, user_role::UserRole},
};

const DEVELOPERS: &str = "configuration:developers";
const CONFIGURATORS: &str = "configuration:configurators";
const EVENT_NAME: &str = "configuration.file-changed.v1";

#[derive(Debug, Deserialize)]
struct RealtimeAuthentication {
    token: String,
}

pub fn configure(
    io: &SocketIo,
    authenticator: Arc<dyn AuthenticateBearerToken>,
    primary_id: String,
    configurator_directory: RelativeStoragePath,
) -> Arc<SocketConfigurationEventDelivery> {
    io.ns(
        "/configuration",
        async move |socket: SocketRef, Data(auth): Data<RealtimeAuthentication>| {
            let principal = match authenticator.authenticate(&auth.token).await {
                Ok(principal) => principal,
                Err(_) => {
                    let _ = socket.disconnect();
                    return;
                }
            };
            let roles = &principal.user.permissions;
            if principal.user.main_group == UserRole::Developer
                || roles.contains(&UserRole::Developer)
            {
                socket.join(DEVELOPERS);
            } else if principal.user.main_group == UserRole::Configurator
                || roles.contains(&UserRole::Configurator)
            {
                socket.join(CONFIGURATORS);
            } else {
                let _ = socket.disconnect();
            }
        },
    );
    Arc::new(SocketConfigurationEventDelivery {
        io: io.clone(),
        primary_id,
        configurator_directory,
    })
}

pub struct SocketConfigurationEventDelivery {
    io: SocketIo,
    primary_id: String,
    configurator_directory: RelativeStoragePath,
}

impl ConfigurationEventDelivery for SocketConfigurationEventDelivery {
    fn deliver<'a>(
        &'a self,
        event: &'a ConfigurationMutationEvent,
    ) -> ConfigurationDeliveryFuture<'a> {
        Box::pin(async move {
            self.io
                .of("/configuration")
                .ok_or("configuration namespace unavailable")?
                .to(DEVELOPERS)
                .emit(EVENT_NAME, &ConfigurationEventResponse::from(event))
                .await
                .map_err(|error| error.to_string())?;
            if let Some(projected) = self.configurator_projection(event) {
                self.io
                    .of("/configuration")
                    .ok_or("configuration namespace unavailable")?
                    .to(CONFIGURATORS)
                    .emit(EVENT_NAME, &projected)
                    .await
                    .map_err(|error| error.to_string())?;
            }
            Ok(())
        })
    }
}

impl SocketConfigurationEventDelivery {
    fn configurator_projection(
        &self,
        event: &ConfigurationMutationEvent,
    ) -> Option<ConfigurationEventResponse> {
        if event.instance_id != self.primary_id {
            return None;
        }
        let project = |path: &Option<String>| -> Option<Option<String>> {
            let Some(path) = path else {
                return Some(None);
            };
            let relative = RelativeStoragePath::new(path).ok()?;
            if !relative.is_within_case_insensitive(&self.configurator_directory) {
                return None;
            }
            let prefix = self.configurator_directory.to_string();
            let projected = if prefix.is_empty() {
                path.clone()
            } else {
                path.get(prefix.len()..)?.trim_start_matches('/').to_owned()
            };
            Some(Some(projected))
        };
        let source = project(&event.source)?;
        let destination = project(&event.destination)?;
        let mut projected = ConfigurationEventResponse::from(event);
        projected.source = source;
        projected.destination = destination;
        Some(projected)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigurationEventResponse {
    schema_version: u16,
    event_id: String,
    mutation_id: String,
    instance_id: String,
    actor_user_id: String,
    occurred_at: String,
    operation: String,
    source: Option<String>,
    destination: Option<String>,
    previous_hash: Option<String>,
    current_hash: Option<String>,
    backup_id: Option<String>,
}

impl From<&ConfigurationMutationEvent> for ConfigurationEventResponse {
    fn from(event: &ConfigurationMutationEvent) -> Self {
        Self {
            schema_version: 1,
            event_id: event.event_id.clone(),
            mutation_id: event.mutation_id.clone(),
            instance_id: event.instance_id.clone(),
            actor_user_id: event.actor_user_id.clone(),
            occurred_at: event.occurred_at.clone(),
            operation: event.operation.clone(),
            source: event.source.clone(),
            destination: event.destination.clone(),
            previous_hash: event.previous_hash.clone(),
            current_hash: event.current_hash.clone(),
            backup_id: event.backup_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(instance_id: &str, path: &str) -> ConfigurationMutationEvent {
        ConfigurationMutationEvent {
            event_id: "configuration.file-changed.v1:id".into(),
            mutation_id: "id".into(),
            instance_id: instance_id.into(),
            actor_user_id: "42".into(),
            actor_session_id: Some("session".into()),
            access_level: "developer".into(),
            operation: "overwrite".into(),
            source: Some(path.into()),
            destination: Some(path.into()),
            previous_hash: None,
            current_hash: None,
            backup_id: None,
            occurred_at: "now".into(),
        }
    }

    #[test]
    fn configurator_projection_hides_other_instances_and_paths() {
        let (_, io) = SocketIo::new_layer();
        let delivery = SocketConfigurationEventDelivery {
            io,
            primary_id: "main".into(),
            configurator_directory: RelativeStoragePath::new("scriptfiles/config").unwrap(),
        };
        assert!(
            delivery
                .configurator_projection(&event("test", "scriptfiles/config/server.cfg"))
                .is_none()
        );
        assert!(
            delivery
                .configurator_projection(&event("main", "private/key.env"))
                .is_none()
        );
        let projected = delivery
            .configurator_projection(&event("main", "scriptfiles/config/server.cfg"))
            .unwrap();
        assert_eq!(projected.source.as_deref(), Some("server.cfg"));
        assert_eq!(projected.destination.as_deref(), Some("server.cfg"));
    }
}
