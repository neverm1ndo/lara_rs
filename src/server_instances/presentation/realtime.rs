use std::sync::Arc;

use serde::{Deserialize, Serialize};
use socketioxide::{
    SocketIo,
    extract::{Data, SocketRef},
    layer::SocketIoLayer,
};

use crate::{
    auth::application::authenticate_jwt::AuthenticateBearerToken,
    server_instances::{
        application::{
            lifecycle_events::{
                LifecycleEventDelivery, LifecycleEventDeliveryError, LifecycleEventDeliveryFuture,
                LifecycleOperationUpdatedEvent, OPERATION_UPDATED_EVENT, STATE_CHANGED_EVENT,
                ServerInstanceEvent, ServerInstanceStateChangedEvent,
            },
            runtime_state::RuntimeStateView,
        },
        domain::LifecycleOperationState,
        presentation::dto::{
            LifecycleActionResponse, LifecycleFailureCodeResponse,
            LifecycleOperationStatusResponse, RuntimeStateResponse,
        },
    },
    shared::user_role::UserRole,
};

const DEVELOPERS_ROOM: &str = "server-instances:developers";
const PRIMARY_GENERAL_ROOM: &str = "server-instances:primary-general";

#[derive(Debug, Deserialize)]
struct RealtimeAuthentication {
    token: String,
}

pub fn configure_socket_io(
    authenticator: Arc<dyn AuthenticateBearerToken>,
) -> (SocketIoLayer, Arc<SocketLifecycleEventDelivery>) {
    let (layer, io) = SocketIo::new_layer();
    io.ns(
        "/",
        async move |socket: SocketRef, Data(auth): Data<RealtimeAuthentication>| {
            let principal = match authenticator.authenticate(&auth.token).await {
                Ok(principal) => principal,
                Err(_) => {
                    let _ = socket.disconnect();
                    return;
                }
            };

            let user = principal.user;
            match realtime_audience(user.main_group, &user.permissions) {
                Some(RealtimeAudience::Developer) => socket.join([
                    DEVELOPERS_ROOM.to_owned(),
                    format!("server-instances:user:{}", user.id),
                ]),
                Some(RealtimeAudience::PrimaryGeneral) => socket.join(PRIMARY_GENERAL_ROOM),
                None => {
                    let _ = socket.disconnect();
                }
            }
        },
    );
    let delivery = Arc::new(SocketLifecycleEventDelivery { io });
    (layer, delivery)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RealtimeAudience {
    Developer,
    PrimaryGeneral,
}

fn realtime_audience(main_group: UserRole, permissions: &[UserRole]) -> Option<RealtimeAudience> {
    if main_group == UserRole::Developer || permissions.contains(&UserRole::Developer) {
        Some(RealtimeAudience::Developer)
    } else if matches!(main_group, UserRole::Admin | UserRole::Challenger)
        || permissions.contains(&UserRole::Admin)
        || permissions.contains(&UserRole::Challenger)
    {
        Some(RealtimeAudience::PrimaryGeneral)
    } else {
        None
    }
}

pub struct SocketLifecycleEventDelivery {
    io: SocketIo,
}

impl LifecycleEventDelivery for SocketLifecycleEventDelivery {
    fn deliver<'a>(&'a self, event: &'a ServerInstanceEvent) -> LifecycleEventDeliveryFuture<'a> {
        Box::pin(async move {
            match event {
                ServerInstanceEvent::OperationUpdated(event) => self
                    .io
                    .to(DEVELOPERS_ROOM)
                    .emit(
                        OPERATION_UPDATED_EVENT,
                        &LifecycleOperationEventResponse::from(event),
                    )
                    .await
                    .map_err(delivery_error),
                ServerInstanceEvent::StateChanged(event) => self
                    .io
                    .to(DEVELOPERS_ROOM)
                    .emit(STATE_CHANGED_EVENT, &RuntimeStateEventResponse::from(event))
                    .await
                    .map_err(delivery_error),
            }
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LifecycleOperationEventResponse {
    schema_version: u16,
    event_id: String,
    sequence: u64,
    occurred_at: String,
    instance_id: String,
    operation: LifecycleOperationEventSnapshot,
}

impl From<&LifecycleOperationUpdatedEvent> for LifecycleOperationEventResponse {
    fn from(event: &LifecycleOperationUpdatedEvent) -> Self {
        let (status, systemd_job) = match event.state() {
            LifecycleOperationState::Requested => {
                (LifecycleOperationStatusResponse::Requested, None)
            }
            LifecycleOperationState::Dispatching => {
                (LifecycleOperationStatusResponse::Dispatching, None)
            }
            LifecycleOperationState::WaitingForState { job } => (
                LifecycleOperationStatusResponse::WaitingForState,
                Some(job.as_str().to_owned()),
            ),
            LifecycleOperationState::Succeeded => {
                (LifecycleOperationStatusResponse::Succeeded, None)
            }
            LifecycleOperationState::Failed { .. } => {
                (LifecycleOperationStatusResponse::Failed, None)
            }
            LifecycleOperationState::TimedOut => (LifecycleOperationStatusResponse::TimedOut, None),
        };
        Self {
            schema_version: 1,
            event_id: event.event_id().to_owned(),
            sequence: event.sequence().get(),
            occurred_at: event.occurred_at().to_rfc3339(),
            instance_id: event.instance_id().to_string(),
            operation: LifecycleOperationEventSnapshot {
                id: event.operation_id().to_string(),
                action: event.action().into(),
                actor_user_id: event.actor_id().get(),
                actor_display_name: event.actor_display_name().to_owned(),
                status,
                systemd_job,
                failure_code: event.failure_code().map(Into::into),
                deadline: event.deadline().to_rfc3339(),
                completed_at: event.completed_at().map(|value| value.to_rfc3339()),
                version: event.sequence().get(),
            },
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LifecycleOperationEventSnapshot {
    id: String,
    action: LifecycleActionResponse,
    actor_user_id: i64,
    actor_display_name: String,
    status: LifecycleOperationStatusResponse,
    systemd_job: Option<String>,
    failure_code: Option<LifecycleFailureCodeResponse>,
    deadline: String,
    completed_at: Option<String>,
    version: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeStateEventResponse {
    schema_version: u16,
    event_id: String,
    sequence: i64,
    state: RuntimeStateResponse,
}

impl From<&ServerInstanceStateChangedEvent> for RuntimeStateEventResponse {
    fn from(event: &ServerInstanceStateChangedEvent) -> Self {
        Self {
            schema_version: 1,
            event_id: event.event_id().to_owned(),
            sequence: event.sequence(),
            state: RuntimeStateResponse::from(RuntimeStateView {
                state: event.state().clone(),
                readiness_mode: event.readiness_mode(),
            }),
        }
    }
}

fn delivery_error(error: impl std::fmt::Display) -> LifecycleEventDeliveryError {
    LifecycleEventDeliveryError::new(error.to_string())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::server_instances::domain::{
        InstanceReadiness, InstanceRuntimeState, ProcessState, ReadinessStatus, ServerInstanceId,
    };

    #[test]
    fn state_event_payload_exposes_stable_envelope() {
        let event = ServerInstanceStateChangedEvent::new(
            InstanceRuntimeState::observed(
                ServerInstanceId::new("dev-dm").unwrap(),
                ProcessState::Active,
                ReadinessStatus::Ready,
                Utc::now(),
                Some(42),
                1,
                Some("invocation".into()),
                None,
            ),
            InstanceReadiness::Process,
            Utc::now(),
        );

        let value = serde_json::to_value(RuntimeStateEventResponse::from(&event)).unwrap();
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["state"]["instanceId"], "dev-dm");
        assert_eq!(value["state"]["process"]["state"], "active");
    }

    #[test]
    fn realtime_rooms_do_not_inherit_developer_from_admin() {
        assert_eq!(
            realtime_audience(UserRole::Admin, &[UserRole::Admin]),
            Some(RealtimeAudience::PrimaryGeneral)
        );
        assert_eq!(
            realtime_audience(UserRole::Admin, &[UserRole::Admin, UserRole::Developer]),
            Some(RealtimeAudience::Developer)
        );
        assert_eq!(
            realtime_audience(UserRole::Mapper, &[UserRole::Mapper]),
            None
        );
    }
}
