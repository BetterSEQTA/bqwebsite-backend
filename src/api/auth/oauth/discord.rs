use axum::{extract::State, response::{IntoResponse, Redirect}};
use url::Url;
use uuid::Uuid;
use crate::{responses::throw_internal_server_error};
use sqlx::{types::chrono, PgPool};

pub async fn define_event_handler(State(state): State<PgPool>) -> impl IntoResponse {
    let client_id = match std::env::var("DISCORD_CLIENT_ID") {
        Ok(e) => e,
        Err(_) => {
            println!("Error getting discord client id!");
            return throw_internal_server_error().await;
        }
    };
    let redirect_uri = match std::env::var("REDIRECT_URI_DISCORD") {
        Ok(e) => e,
        Err(_) => {
            println!("Error getting redirect URI");
            return throw_internal_server_error().await;
        }
    };

    let response_type = "code";
    let scope = "email identify openid connections";

    let state_call = Uuid::new_v4();
    let current_time = chrono::Utc::now();

    let mut url = match Url::parse("https://discord.com/oauth2/authorize") {
        Ok(e) => e,
        Err(e) => {
            println!("Failed to parse discord url: {}", e);
            return throw_internal_server_error().await;
        }
    };
    url.query_pairs_mut()
        .append_pair("client_id", &client_id)
        .append_pair("response_type", &response_type)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", &scope)
        .append_pair("state", &state_call.to_string());

    let _ = match sqlx::query(r#"
    INSERT INTO state (state, created_at)
    VALUES ($1, $2)
    "#)
    .bind(&state_call)
    .bind(&current_time)
    .execute(&state)
    .await
    {
        Ok(_) => {
            return Redirect::to(url.as_str()).into_response();
        },
        Err(e) => {
            println!("Couldn't create state in Discord Callback!: {}", e);
            return throw_internal_server_error().await;
        }
    };
}
