use serde::{Serialize, Deserialize};
use uuid::Uuid;
use sqlx::types::chrono::Utc;
use axum::http::StatusCode;

#[derive(Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "provider", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
#[derive(Debug)]
pub enum Provider {
    Discord,
    Google,
    Microsoft
}

pub struct AuthError {
    pub message: String,
    pub status_code: StatusCode,
}

#[derive(Serialize, Deserialize)]
pub struct User {
    pub userid: Uuid,
    pub email: String,
    pub provider: Provider,
    #[serde(rename = "accessToken")]
    pub access_token: String,

    #[serde(rename = "refreshToken")]
    pub refresh_token: String,

    #[serde(rename = "providerId")]
    pub provider_name: Option<String>,

    pub username: String,

    #[serde(rename = "displayName")]
    pub display_name: Option<String>,

    #[serde(rename = "pfpUrl")]
    pub pfp_url: Option<String>,

    #[serde(rename = "createdAt")]
    pub created_at: chrono::DateTime<Utc>,

    #[serde(rename = "tokenExpiresAt")]
    pub token_expires_at: Option<chrono::DateTime<Utc>>

}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Token {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub toktype: String,
}

#[derive(Debug, Deserialize)]
pub struct DiscordCallbackQuery {
    pub code: String,
    pub state: Uuid
}

#[derive(Debug, Deserialize)]
pub struct DiscordAccessTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<i64>,
    pub refresh_token: String,
    pub scope: String
}

#[derive(Debug, Deserialize)]
pub struct DiscordUser {
    pub id: String,
    pub username: String,
    pub global_name: Option<String>,
    pub email: Option<String>,
    pub avatar: Option<String>,
    pub verified: bool
}
