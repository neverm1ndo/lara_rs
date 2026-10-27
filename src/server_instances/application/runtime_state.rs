use std::sync::Arc;

use thiserror::Error;

use crate::{
    server_instances::{
        application::registry::InstanceRegistry,
        domain::{InstanceReadiness, InstanceRuntimeState, ServerInstanceId},
    },
    shared::user_role::UserRole,
};

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("runtime state repository is unavailable")]
pub struct RuntimeStateRepositoryError;

pub trait RuntimeStateReader: Send + Sync {
    fn get(
        &self,
        instance_id: &ServerInstanceId,
    ) -> Result<Option<InstanceRuntimeState>, RuntimeStateRepositoryError>;
}

pub trait RuntimeStateWriter: Send + Sync {
    fn put(&self, state: InstanceRuntimeState) -> Result<(), RuntimeStateRepositoryError>;
}

#[derive(Debug, Clone)]
pub struct RuntimeStateSubject {
    main_group: UserRole,
    permissions: Vec<UserRole>,
}

impl RuntimeStateSubject {
    pub fn new(main_group: UserRole, permissions: Vec<UserRole>) -> Self {
        Self {
            main_group,
            permissions,
        }
    }

    fn is_developer(&self) -> bool {
        self.main_group == UserRole::Developer || self.permissions.contains(&UserRole::Developer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStateView {
    pub state: InstanceRuntimeState,
    pub readiness_mode: InstanceReadiness,
}

pub struct GetRuntimeStateService {
    registry: Arc<dyn InstanceRegistry>,
    states: Arc<dyn RuntimeStateReader>,
}

impl GetRuntimeStateService {
    pub fn new(registry: Arc<dyn InstanceRegistry>, states: Arc<dyn RuntimeStateReader>) -> Self {
        Self { registry, states }
    }

    pub fn get(
        &self,
        subject: &RuntimeStateSubject,
        instance_id: &ServerInstanceId,
    ) -> Result<RuntimeStateView, GetRuntimeStateError> {
        if !subject.is_developer() {
            return Err(GetRuntimeStateError::Forbidden);
        }
        let instance = self
            .registry
            .get(instance_id)
            .ok_or(GetRuntimeStateError::NotFound)?;
        let state = self
            .states
            .get(instance_id)?
            .unwrap_or_else(|| InstanceRuntimeState::not_observed(instance_id.clone()));

        Ok(RuntimeStateView {
            state,
            readiness_mode: instance.observability().readiness(),
        })
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum GetRuntimeStateError {
    #[error("developer role is required")]
    Forbidden,
    #[error("server instance does not exist")]
    NotFound,
    #[error("runtime state is unavailable")]
    Unavailable,
}

impl From<RuntimeStateRepositoryError> for GetRuntimeStateError {
    fn from(_: RuntimeStateRepositoryError) -> Self {
        Self::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_instances::domain::{
        InstanceCapabilities, InstanceClassification, InstanceEnvironment, InstanceKind,
        InstanceManagement, InstanceObservability, ObservationStatus, ServerInstance,
    };

    struct Registry(ServerInstance);

    impl InstanceRegistry for Registry {
        fn primary(&self) -> ServerInstance {
            self.0.clone()
        }

        fn get(&self, id: &ServerInstanceId) -> Option<ServerInstance> {
            (self.0.id() == id).then(|| self.0.clone())
        }

        fn list(&self) -> Vec<ServerInstance> {
            vec![self.0.clone()]
        }
    }

    struct States(Option<InstanceRuntimeState>);

    impl RuntimeStateReader for States {
        fn get(
            &self,
            _instance_id: &ServerInstanceId,
        ) -> Result<Option<InstanceRuntimeState>, RuntimeStateRepositoryError> {
            Ok(self.0.clone())
        }
    }

    fn service(state: Option<InstanceRuntimeState>) -> GetRuntimeStateService {
        let instance = ServerInstance::new(
            ServerInstanceId::new("main").unwrap(),
            "Main",
            InstanceClassification::new(
                InstanceKind::Primary,
                InstanceEnvironment::Production,
                InstanceManagement::External,
            ),
            10,
            InstanceCapabilities::primary(),
            InstanceObservability::new(InstanceReadiness::Uds, true),
        )
        .unwrap();
        GetRuntimeStateService::new(Arc::new(Registry(instance)), Arc::new(States(state)))
    }

    fn subject(role: UserRole) -> RuntimeStateSubject {
        RuntimeStateSubject::new(role, vec![role])
    }

    #[test]
    fn reports_not_observed_before_the_first_adapter_snapshot() {
        let id = ServerInstanceId::new("main").unwrap();
        let view = service(None)
            .get(&subject(UserRole::Developer), &id)
            .unwrap();

        assert_eq!(view.state.observation(), ObservationStatus::NotObserved);
        assert_eq!(view.readiness_mode, InstanceReadiness::Uds);
    }

    #[test]
    fn requires_developer_from_main_group_or_permissions() {
        let id = ServerInstanceId::new("main").unwrap();
        assert_eq!(
            service(None).get(&subject(UserRole::Admin), &id),
            Err(GetRuntimeStateError::Forbidden)
        );
        assert!(
            service(None)
                .get(
                    &RuntimeStateSubject::new(
                        UserRole::Admin,
                        vec![UserRole::Admin, UserRole::Developer],
                    ),
                    &id,
                )
                .is_ok()
        );
    }

    #[test]
    fn rejects_unknown_instances() {
        let result = service(None).get(
            &subject(UserRole::Developer),
            &ServerInstanceId::new("missing").unwrap(),
        );

        assert_eq!(result, Err(GetRuntimeStateError::NotFound));
    }
}
