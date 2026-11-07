use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::server_instances::{
    application::incident_management::{
        IncidentFilters, IncidentListPage, IncidentListRequest, ReviewResult,
    },
    domain::{Incident, IncidentEvidence, IncidentOperationalState, IncidentReviewState},
};

#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct IncidentListParameters {
    pub operational_state: Option<String>,
    pub review_state: Option<String>,
    pub opened_from: Option<String>,
    pub opened_to: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

impl IncidentListParameters {
    pub fn into_request(self) -> Result<IncidentListRequest, ()> {
        let operational_state = self
            .operational_state
            .map(|value| match value.as_str() {
                "open" => Ok(IncidentOperationalState::Open),
                "recovering" => Ok(IncidentOperationalState::Recovering),
                "resolved" => Ok(IncidentOperationalState::Resolved),
                _ => Err(()),
            })
            .transpose()?;
        let review_state = self
            .review_state
            .map(|value| match value.as_str() {
                "unreviewed" => Ok(IncidentReviewState::Unreviewed),
                "acknowledged" => Ok(IncidentReviewState::Acknowledged),
                "investigated" => Ok(IncidentReviewState::Investigated),
                _ => Err(()),
            })
            .transpose()?;
        let parse_time = |value: String| {
            chrono::DateTime::parse_from_rfc3339(&value)
                .map(|time| time.with_timezone(&chrono::Utc))
                .map_err(|_| ())
        };
        Ok(IncidentListRequest {
            filters: IncidentFilters {
                operational_state,
                review_state,
                opened_from: self.opened_from.map(parse_time).transpose()?,
                opened_to: self.opened_to.map(parse_time).transpose()?,
            },
            cursor: self.cursor,
            limit: self.limit,
        })
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IncidentListResponse {
    pub schema_version: u16,
    pub items: Vec<IncidentResponse>,
    pub next_cursor: Option<String>,
}

impl From<IncidentListPage> for IncidentListResponse {
    fn from(page: IncidentListPage) -> Self {
        Self {
            schema_version: 1,
            items: page.items.iter().map(IncidentResponse::from).collect(),
            next_cursor: page.next_cursor,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IncidentResponse {
    pub schema_version: u16,
    pub incident_id: String,
    pub instance_id: String,
    pub kind: String,
    pub cause: String,
    pub confidence: String,
    pub operational_state: String,
    pub review_state: String,
    pub opened_at: String,
    pub recovered_at: Option<String>,
    pub updated_at: String,
    pub version: u64,
    pub evidence: Vec<IncidentEvidenceResponse>,
    pub related_operation_ids: Vec<String>,
    pub review: Vec<IncidentReviewEntryResponse>,
}

impl From<&Incident> for IncidentResponse {
    fn from(value: &Incident) -> Self {
        Self {
            schema_version: 1,
            incident_id: value.id().to_string(),
            instance_id: value.instance_id().to_string(),
            kind: enum_name(&value.kind()),
            cause: enum_name(&value.cause()),
            confidence: enum_name(&value.confidence()),
            operational_state: enum_name(&value.operational_state()),
            review_state: enum_name(&value.review_state()),
            opened_at: value.opened_at().to_rfc3339(),
            recovered_at: value.recovered_at().map(|time| time.to_rfc3339()),
            updated_at: value.updated_at().to_rfc3339(),
            version: value.version(),
            evidence: value
                .evidence()
                .iter()
                .map(IncidentEvidenceResponse::from)
                .collect(),
            related_operation_ids: value
                .related_operation_ids()
                .iter()
                .map(ToString::to_string)
                .collect(),
            review: value
                .review_history()
                .iter()
                .map(|entry| IncidentReviewEntryResponse {
                    actor_user_id: entry.reviewer_id().get(),
                    state: enum_name(&entry.state()),
                    note: entry.note().to_owned(),
                    at: entry.at().to_rfc3339(),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IncidentEvidenceResponse {
    pub source: String,
    pub occurred_at: String,
    pub process: String,
    pub invocation_id: Option<String>,
    pub restart_count: Option<u32>,
    pub termination_kind: Option<String>,
    pub termination_status: Option<i32>,
    pub confidence: String,
}

impl From<&IncidentEvidence> for IncidentEvidenceResponse {
    fn from(value: &IncidentEvidence) -> Self {
        Self {
            source: match value.fact_id() {
                crate::server_instances::domain::IncidentFactId::Journal { .. } => "journal",
                crate::server_instances::domain::IncidentFactId::Live { .. } => "live",
            }
            .into(),
            occurred_at: value.occurred_at().to_rfc3339(),
            process: enum_name(&value.process()),
            invocation_id: value.invocation_id().map(str::to_owned),
            restart_count: value.restart_count(),
            termination_kind: value
                .termination()
                .map(|termination| enum_name(&termination.kind())),
            termination_status: value
                .termination()
                .and_then(|termination| termination.status()),
            confidence: enum_name(&value.confidence()),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IncidentReviewEntryResponse {
    pub actor_user_id: i64,
    pub state: String,
    pub note: String,
    pub at: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChangeIncidentReviewRequest {
    pub review_state: ReviewStateRequest,
    pub note: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStateRequest {
    Acknowledged,
    Investigated,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChangeIncidentReviewResponse {
    pub schema_version: u16,
    pub incident_id: String,
    pub version: u64,
    pub review_state: String,
    pub actor_user_id: i64,
    pub note: String,
    pub updated_at: String,
}

impl From<ReviewResult> for ChangeIncidentReviewResponse {
    fn from(value: ReviewResult) -> Self {
        Self {
            schema_version: 1,
            incident_id: value.incident_id.to_string(),
            version: value.version,
            review_state: enum_name(&value.state),
            actor_user_id: value.actor_user_id,
            note: value.note,
            updated_at: value.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IncidentErrorResponse {
    pub code: &'static str,
}

fn enum_name<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .expect("domain enum serializes")
        .as_str()
        .expect("domain enum is a string")
        .to_owned()
}
