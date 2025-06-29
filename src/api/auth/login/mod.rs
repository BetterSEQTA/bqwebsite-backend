use ::chrono::Utc;
use sqlx::{postgres::{PgQueryResult, PgRow}, types::chrono, Executor, PgPool};

use axum::{extract::State, handler::Handler, http::StatusCode, Error, Json, response::{IntoResponse, Response}};
use uuid::Uuid;

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "provider")] // Use your actual Postgres enum name here
#[sqlx(rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Discord,
    Credentials
}

#[derive(Serialize, Deserialize)]
pub struct User {
    userid: Option<Uuid>,
    email: Option<String>,
    password: Option<String>,
    provider: Option<Provider>,
    #[serde(rename = "providerId")]
    provider_id: Option<String>,
    username: Option<String>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "pfpUrl")]
    pfp_url: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: Option<chrono::DateTime<Utc>>

}

pub async fn login(State(state): State<PgPool>) -> Json<Vec<User>> {
    let result = sqlx::query_as!(
        User,
        r#"
        SELECT 
            userid,
            email,
            password,
            provider::TEXT as "provider: _", 
            "providerId" as provider_id,
            username,
            "displayName" as display_name,
            "pfpUrl" as pfp_url,
            "createdAt" as created_at
        FROM users
        "#
    )
    .fetch_all(&state)
    .await
    .expect("Login malfunctioned");
    
    Json(result)
}