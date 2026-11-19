//! Typed read envelopes; grid serialization happens after API validation.
use super::*;
pub use crate::state::use_api_typed;
use crate::state::ApiResource;
use leptos::prelude::*;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged, bound(deserialize = "T: Deserialize<'de> + Default"))]
pub enum Records<T> {
    List(Vec<T>),
    Envelope(RecordEnvelope<T>),
}
impl<T> Default for Records<T> {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, bound(deserialize = "T: Deserialize<'de> + Default"))]
pub struct RecordEnvelope<T> {
    #[serde(
        alias = "users",
        alias = "quotas",
        alias = "nodes",
        alias = "apps",
        alias = "data",
        alias = "results",
        deserialize_with = "nullable"
    )]
    pub items: Vec<T>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct PendingCount {
    pub total: Option<u64>,
    pub count: Option<u64>,
}
impl PendingCount {
    pub fn reported_total(&self) -> Option<u64> {
        self.total.or(self.count)
    }
}

/// Complete a shared model's missing fields while preserving legacy extension
/// fields (for example memory.total_gb) used by older snapshot producers.
#[derive(Clone, Debug, Default)]
pub struct SharedRecord<T> {
    pub model: T,
    pub extensions: BTreeMap<String, Value>,
}
impl<'de, T: DeserializeOwned + Serialize + Default> Deserialize<'de> for SharedRecord<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let extensions = BTreeMap::<String, Value>::deserialize(deserializer)?;
        let value = serde_json::to_value(&extensions).map_err(serde::de::Error::custom)?;
        let model = shared_model(&value)
            .ok_or_else(|| serde::de::Error::custom("Invalid shared record"))?;
        Ok(Self { model, extensions })
    }
}
impl<T: Serialize> Serialize for SharedRecord<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serde_json::to_value(&self.model).map_err(serde::ser::Error::custom)?;
        if let Some(fields) = value.as_object_mut() {
            fields.extend(self.extensions.clone());
        }
        value.serialize(serializer)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct HardwareEnvelope {
    pub system_vendor: String,
    pub system_product: String,
    pub cpu: Option<SharedRecord<af_models::CpuInfo>>,
    pub memory: Option<MemoryRecord>,
    #[serde(deserialize_with = "nullable")]
    pub storage: Vec<SharedRecord<af_models::StorageInfo>>,
    #[serde(deserialize_with = "nullable")]
    pub gpus: Vec<SharedRecord<af_models::GpuInfo>>,
    #[serde(deserialize_with = "nullable")]
    pub network: Vec<SharedRecord<af_models::NetworkInfo>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct MemoryRecord {
    pub total_bytes: i64,
    #[serde(deserialize_with = "bank_count")]
    pub banks: i32,
    #[serde(rename = "type")]
    pub mem_type: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
fn bank_count<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i32, D::Error> {
    let value = Value::deserialize(deserializer)?;
    let count = match value {
        Value::Array(items) => items.len() as i64,
        Value::Null => 0,
        other => other
            .as_i64()
            .ok_or_else(|| serde::de::Error::custom("Invalid memory bank count"))?,
    };
    i32::try_from(count).map_err(serde::de::Error::custom)
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct TopologyEnvelope {
    #[serde(deserialize_with = "nullable")]
    pub nodes: Vec<TopologyRecord>,
    #[serde(alias = "links", deserialize_with = "nullable")]
    pub edges: Vec<TopologyEdge>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct TopologyRecord {
    pub id: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct TopologyEdge {
    #[serde(alias = "from")]
    pub source: String,
    #[serde(alias = "to")]
    pub target: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Existing grids and feedback widgets share JSON presentation state. They only
/// receive snapshots that have passed the endpoint's typed serde contract.
pub fn grid_resource<T: Clone + Serialize + Send + Sync + 'static>(
    resource: ApiResource<T>,
) -> ApiResource {
    let data = RwSignal::new(Value::Null);
    Effect::new(move |_| {
        if resource.loading.get() && data.with_untracked(Value::is_null) {
            return;
        }
        data.set(serde_json::to_value(resource.data.get()).unwrap_or_default());
    });
    ApiResource {
        data,
        loading: resource.loading,
        error: resource.error,
        revision: resource.revision,
    }
}
