use std::{collections::BTreeMap, sync::RwLock};

use crate::server_instances::{
    application::runtime_state::{
        RuntimeStateReader, RuntimeStateRepositoryError, RuntimeStateWriter,
    },
    domain::{InstanceRuntimeState, ServerInstanceId},
};

#[derive(Debug, Default)]
pub struct InMemoryRuntimeStateStore {
    states: RwLock<BTreeMap<ServerInstanceId, InstanceRuntimeState>>,
}

impl InMemoryRuntimeStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RuntimeStateReader for InMemoryRuntimeStateStore {
    fn get(
        &self,
        instance_id: &ServerInstanceId,
    ) -> Result<Option<InstanceRuntimeState>, RuntimeStateRepositoryError> {
        self.states
            .read()
            .map_err(|_| RuntimeStateRepositoryError)
            .map(|states| states.get(instance_id).cloned())
    }
}

impl RuntimeStateWriter for InMemoryRuntimeStateStore {
    fn put(&self, state: InstanceRuntimeState) -> Result<(), RuntimeStateRepositoryError> {
        self.states
            .write()
            .map_err(|_| RuntimeStateRepositoryError)?
            .insert(state.instance_id().clone(), state);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::server_instances::domain::{ProcessState, ReadinessStatus};

    #[test]
    fn stores_independent_latest_snapshots_by_typed_instance_id() {
        let store = InMemoryRuntimeStateStore::new();
        let main = InstanceRuntimeState::observed(
            ServerInstanceId::new("main").unwrap(),
            ProcessState::Active,
            ReadinessStatus::Ready,
            Utc::now(),
            Some(42),
            1,
            Some("invocation-1".into()),
            None,
        );
        store.put(main.clone()).unwrap();

        assert_eq!(
            store.get(&ServerInstanceId::new("main").unwrap()).unwrap(),
            Some(main)
        );
        assert!(
            store
                .get(&ServerInstanceId::new("dev-dm").unwrap())
                .unwrap()
                .is_none()
        );
    }
}
