use mongodb::{
    Collection, Database, IndexModel,
    bson::{self, doc},
    error::{Error as MongoError, ErrorKind, WriteFailure},
    options::{IndexOptions, ReturnDocument},
};

use crate::configuration::application::mutation_log::{
    ConfigurationMutationLog, ConfigurationMutationLogError, ConfigurationMutationRecord,
    ConfigurationMutationState, MutationLogFuture,
};

pub struct MongoConfigurationMutationLog {
    records: Collection<ConfigurationMutationRecord>,
}

impl MongoConfigurationMutationLog {
    pub fn new(database: Database) -> Self {
        Self {
            records: database.collection("configuration_mutations"),
        }
    }

    pub async fn ensure_indexes(&self) -> Result<(), ConfigurationMutationLogError> {
        let idempotency = IndexModel::builder()
            .keys(doc! {"actor_user_id": 1, "idempotency_key": 1})
            .options(
                IndexOptions::builder()
                    .name(Some("configuration_actor_key_unique".into()))
                    .unique(Some(true))
                    .build(),
            )
            .build();
        let active_path = IndexModel::builder()
            .keys(doc! {"active_path": 1})
            .options(
                IndexOptions::builder()
                    .name(Some("configuration_active_path_unique".into()))
                    .unique(Some(true))
                    .partial_filter_expression(Some(doc! {"active_path": {"$type": "string"}}))
                    .build(),
            )
            .build();
        let history = IndexModel::builder()
            .keys(doc! {"instance_id": 1, "created_at": -1})
            .options(
                IndexOptions::builder()
                    .name(Some("configuration_instance_history".into()))
                    .build(),
            )
            .build();
        let outbox = IndexModel::builder()
            .keys(doc! {"state": 1, "delivered_at": 1, "delivery_lease_until": 1})
            .options(
                IndexOptions::builder()
                    .name(Some("configuration_outbox".into()))
                    .build(),
            )
            .build();
        self.records
            .create_indexes([idempotency, active_path, history, outbox])
            .await
            .map_err(database_error)?;
        Ok(())
    }
}

impl ConfigurationMutationLog for MongoConfigurationMutationLog {
    fn reserve<'a>(&'a self, record: &'a ConfigurationMutationRecord) -> MutationLogFuture<'a, ()> {
        Box::pin(async move {
            match self.records.insert_one(record).await {
                Ok(_) => Ok(()),
                Err(error) if duplicate_key(&error) => {
                    Err(ConfigurationMutationLogError::AlreadyExists)
                }
                Err(error) => Err(database_error(error)),
            }
        })
    }

    fn by_key<'a>(
        &'a self,
        actor: &'a str,
        key: &'a str,
    ) -> MutationLogFuture<'a, Option<ConfigurationMutationRecord>> {
        Box::pin(async move {
            self.records
                .find_one(doc! {"actor_user_id": actor, "idempotency_key": key})
                .await
                .map_err(database_error)
        })
    }

    fn by_id<'a>(
        &'a self,
        id: &'a str,
    ) -> MutationLogFuture<'a, Option<ConfigurationMutationRecord>> {
        Box::pin(async move {
            self.records
                .find_one(doc! {"_id": id})
                .await
                .map_err(database_error)
        })
    }

    fn transition<'a>(
        &'a self,
        id: &'a str,
        from: ConfigurationMutationState,
        next: ConfigurationMutationRecord,
    ) -> MutationLogFuture<'a, bool> {
        Box::pin(async move {
            let from = bson::to_bson(&from)
                .map_err(|error| ConfigurationMutationLogError::Unavailable(error.to_string()))?;
            let replacement = self
                .records
                .replace_one(doc! {"_id": id, "state": from}, next)
                .await
                .map_err(database_error)?;
            Ok(replacement.modified_count == 1)
        })
    }

    fn unresolved<'a>(&'a self) -> MutationLogFuture<'a, Vec<ConfigurationMutationRecord>> {
        Box::pin(async move {
            let mut cursor = self
                .records
                .find(doc! {"state": {"$in": ["requested", "applying"]}})
                .await
                .map_err(database_error)?;
            let mut records = Vec::new();
            while cursor.advance().await.map_err(database_error)? {
                records.push(cursor.deserialize_current().map_err(database_error)?);
            }
            Ok(records)
        })
    }

    fn claim_event<'a>(
        &'a self,
        token: &'a str,
        now: &'a str,
        until: &'a str,
    ) -> MutationLogFuture<'a, Option<ConfigurationMutationRecord>> {
        Box::pin(async move {
            self.records.find_one_and_update(
                doc! {"state": "succeeded", "event": {"$ne": bson::Bson::Null}, "delivered_at": bson::Bson::Null,
                    "$or": [{"delivery_lease_until": bson::Bson::Null}, {"delivery_lease_until": {"$lt": now}}]},
                doc! {"$set": {"delivery_lease_until": until, "delivery_lease_token": token}},
            ).return_document(ReturnDocument::After).await.map_err(database_error)
        })
    }

    fn acknowledge_event<'a>(
        &'a self,
        id: &'a str,
        token: &'a str,
        now: &'a str,
    ) -> MutationLogFuture<'a, ()> {
        Box::pin(async move {
            self.records.update_one(doc! {"_id": id, "delivery_lease_token": token, "delivered_at": bson::Bson::Null},
                doc! {"$set": {"delivered_at": now}, "$unset": {"delivery_lease_until": "", "delivery_lease_token": ""}}).await.map_err(database_error)?;
            Ok(())
        })
    }
}

fn database_error(error: impl std::fmt::Display) -> ConfigurationMutationLogError {
    ConfigurationMutationLogError::Unavailable(error.to_string())
}

fn duplicate_key(error: &MongoError) -> bool {
    match error.kind.as_ref() {
        ErrorKind::Write(WriteFailure::WriteError(write)) => write.code == 11_000,
        ErrorKind::BulkWrite(bulk) => bulk
            .write_errors
            .iter()
            .any(|(_, write)| write.code == 11_000),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::application::mutation_log::ConfigurationMutationEvent;

    fn record(id: &str, key: &str, active_path: Option<&str>) -> ConfigurationMutationRecord {
        ConfigurationMutationRecord {
            id: id.into(),
            actor_user_id: "operator-1".into(),
            idempotency_key: key.into(),
            fingerprint: format!("fingerprint-{key}"),
            instance_id: "test".into(),
            operation: "overwrite".into(),
            source: Some("server.cfg".into()),
            destination: None,
            expected_hash: Some("sha256:before".into()),
            desired_hash: Some("sha256:after".into()),
            active_path: active_path.map(str::to_owned),
            state: ConfigurationMutationState::Requested,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            event: None,
            failure_code: None,
            delivered_at: None,
            delivery_lease_until: None,
            delivery_lease_token: None,
            review: None,
        }
    }

    #[tokio::test]
    #[ignore = "requires an isolated MongoDB URI in LARA_TEST_MONGODB_URI"]
    async fn mongo_indexes_recovery_and_outbox_leases() {
        let uri = std::env::var("LARA_TEST_MONGODB_URI")
            .expect("set LARA_TEST_MONGODB_URI to an isolated test MongoDB");
        let client = mongodb::Client::with_uri_str(&uri).await.unwrap();
        let database = client.database(&format!(
            "lara_release_c_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let log = MongoConfigurationMutationLog::new(database.clone());
        log.ensure_indexes().await.unwrap();

        let first = record("first", "key-1", Some("test:server.cfg"));
        log.reserve(&first).await.unwrap();
        assert_eq!(
            log.by_key("operator-1", "key-1").await.unwrap().unwrap().id,
            "first"
        );
        assert!(matches!(
            log.reserve(&record("duplicate-key", "key-1", None)).await,
            Err(ConfigurationMutationLogError::AlreadyExists)
        ));
        assert!(matches!(
            log.reserve(&record("duplicate-path", "key-2", Some("test:server.cfg")))
                .await,
            Err(ConfigurationMutationLogError::AlreadyExists)
        ));

        let mut applying = first.clone();
        applying.state = ConfigurationMutationState::Applying;
        assert!(
            log.transition(
                "first",
                ConfigurationMutationState::Requested,
                applying.clone()
            )
            .await
            .unwrap()
        );
        assert!(
            !log.transition(
                "first",
                ConfigurationMutationState::Requested,
                applying.clone()
            )
            .await
            .unwrap()
        );
        assert_eq!(log.unresolved().await.unwrap().len(), 1);
        applying.state = ConfigurationMutationState::ReconciliationRequired;
        assert!(
            log.transition(
                "first",
                ConfigurationMutationState::Applying,
                applying.clone()
            )
            .await
            .unwrap()
        );
        assert!(log.unresolved().await.unwrap().is_empty());
        assert!(matches!(
            log.reserve(&record("still-locked", "key-3", Some("test:server.cfg")))
                .await,
            Err(ConfigurationMutationLogError::AlreadyExists)
        ));
        applying.state = ConfigurationMutationState::Reviewed;
        applying.active_path = None;
        assert!(
            log.transition(
                "first",
                ConfigurationMutationState::ReconciliationRequired,
                applying
            )
            .await
            .unwrap()
        );
        log.reserve(&record("new-intent", "key-4", Some("test:server.cfg")))
            .await
            .unwrap();

        let mut succeeded = record("event", "key-5", None);
        succeeded.state = ConfigurationMutationState::Succeeded;
        succeeded.event = Some(ConfigurationMutationEvent {
            event_id: "event-1".into(),
            mutation_id: "event".into(),
            instance_id: "test".into(),
            actor_user_id: "operator-1".into(),
            actor_session_id: None,
            access_level: "developer".into(),
            operation: "overwrite".into(),
            source: Some("server.cfg".into()),
            destination: None,
            previous_hash: Some("sha256:before".into()),
            current_hash: Some("sha256:after".into()),
            backup_id: None,
            occurred_at: "2026-01-01T00:00:00Z".into(),
        });
        log.reserve(&succeeded).await.unwrap();
        assert_eq!(
            log.claim_event("lease-1", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
                .await
                .unwrap()
                .unwrap()
                .id,
            "event"
        );
        assert!(
            log.claim_event("lease-2", "2026-01-01T12:00:00Z", "2026-01-02T12:00:00Z")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            log.claim_event("lease-2", "2026-01-03T00:00:00Z", "2026-01-04T00:00:00Z")
                .await
                .unwrap()
                .unwrap()
                .delivery_lease_token
                .as_deref(),
            Some("lease-2")
        );
        log.acknowledge_event("event", "lease-1", "2026-01-03T00:00:00Z")
            .await
            .unwrap();
        assert!(
            log.by_id("event")
                .await
                .unwrap()
                .unwrap()
                .delivered_at
                .is_none()
        );
        log.acknowledge_event("event", "lease-2", "2026-01-03T00:00:00Z")
            .await
            .unwrap();
        assert!(
            log.claim_event("lease-3", "2026-01-05T00:00:00Z", "2026-01-06T00:00:00Z")
                .await
                .unwrap()
                .is_none()
        );
        database.drop().await.unwrap();
    }
}
