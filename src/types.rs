use serde::{Serialize, Deserialize};
use uuid::Uuid;
use sqlx::types::chrono::Utc;

#[derive(Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "provider", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Discord,
    Credentials
}

#[derive(Serialize, Deserialize)]
pub struct User {
    pub userid: Option<Uuid>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub provider: Option<Provider>,
    #[serde(rename = "providerId")]
    pub provider_id: Option<String>,
    pub username: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "pfpUrl")]
    pub pfp_url: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<chrono::DateTime<Utc>>

}

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub username: String,
    pub email: String
}

#[derive(Deserialize)]
pub struct RegisterPayload {
    pub email: String,
    pub password: String,
    pub username: String,
    #[serde(default)]
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
}