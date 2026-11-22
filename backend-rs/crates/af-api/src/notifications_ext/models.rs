use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RegenerateRecoveryReq {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CreateRuleReq {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub condition_type: String,
    #[serde(default)]
    pub condition_value: String,
    #[serde(default = "default_rule_level")]
    pub level: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct UpdateRuleReq {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub condition_type: Option<String>,
    #[serde(default)]
    pub condition_value: Option<String>,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CreateChannelReq {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type", default)]
    pub channel_type: String,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredChannel {
    pub id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub channel_type: String,
    pub config: String,
    pub enabled: bool,
    pub created_at: String,
}

fn default_rule_level() -> String {
    "warning".into()
}
