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
