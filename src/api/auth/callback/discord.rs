use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::{self, State}, http::StatusCode, response::{IntoResponse, Redirect}, Json};
use ::chrono::{DateTime, Duration, SecondsFormat, Utc};
use sqlx::{postgres::PgRow, types::chrono, PgPool, Row};

use reqwest::{header};
use url::Url;

use serde_json::json;
use uuid::Uuid;

use jsonwebtoken::{ Header, EncodingKey };

use crate::{responses::throw_internal_server_error, types::{DiscordAccessTokenResponse, DiscordCallbackQuery, DiscordUser, Provider, Token}};

pub async fn exchange_code(State(state): State<PgPool>, extract::Query(query): extract::Query<DiscordCallbackQuery>) -> impl IntoResponse {
    let query_state = query.state;
    let query_code = query.code;

    let client_id = match std::env::var("DISCORD_CLIENT_ID") {
        Ok(e) => e,
        Err(_) => {
            println!("Error getting discord client id!");
            return throw_internal_server_error().await;
        }
    };
    let client_secret = match std::env::var("DISCORD_SECRET") {
        Ok(e) => e,
        Err(_) => {
            println!("Error getting Discord Secret");
            return throw_internal_server_error().await;
        }
    };

    let db_state = sqlx::query(r#"
    SELECT created_at FROM state
    WHERE state = $1;
    "#)
    .bind(&query_state)
    .fetch_optional(&state)
    .await;

    let _ = sqlx::query(r#"
        DELETE FROM state WHERE state = $1
        "#
    )
        .bind(&query_state)
        .execute(&state)
        .await;

    let created_at: DateTime<Utc> = match &db_state {
        Ok(Some(record)) => record.get("created_at"),
        Ok(None) => return (StatusCode::BAD_REQUEST, "Invalid state token").into_response(),
        Err(e) => {
            println!("Error getting creation date for state token in callback: {}", e);
            return throw_internal_server_error().await;
        }
    };

    let now = chrono::Utc::now();
    if now.signed_duration_since(&created_at).num_minutes() > 15 {
        return (StatusCode::BAD_REQUEST, "State token expired").into_response();
    }

    let redirect_uri = match std::env::var("REDIRECT_URI_DISCORD") {
        Ok(e) => e,
        Err(_) => {
            println!("Error getting redirect URI");
            return throw_internal_server_error().await;
        }
    };

    let params = [("grant_type", "authorization_code"), ("code", &query_code), ("redirect_uri", &redirect_uri)];
    let client = reqwest::Client::new();

    let res_token = match client.post("https://discord.com/api/oauth2/token")
        .form(&params)
        .basic_auth(&client_id, Some(&client_secret))
        .send()
        .await
        {
            Ok(e) => e,
            Err(e) => {
                println!("Error doing access token exchange with Discord: {}", e);
                return throw_internal_server_error().await;
            }
        };

    let res_json = match res_token.json::<DiscordAccessTokenResponse>().await {
        Ok(e) => e,
        Err(e) => {
            println!("Problem deserialising the JSON of Discord Token response: {}", e);
            return throw_internal_server_error().await;
        }
    };

    let res_me = match client.get("https://discord.com/api/users/@me")
        .bearer_auth(&res_json.access_token)
        .send()
        .await 
    {
        Ok(e) => e,
        Err(e) => {
            println!("Error getting user info from Discord: {}", e);
            return throw_internal_server_error().await;
        }
    };

    let mut me_json = match res_me.json::<DiscordUser>().await {
        Ok(e) => e,
        Err(e) => {
            println!("Error parsing user info as JSON from Discord: {}", e);
            return throw_internal_server_error().await;
        }
    };

    if !me_json.verified || me_json.email.is_none() {
        return (StatusCode::BAD_REQUEST, Json(json!({"status": "400", "message": "Your Discord account doesn't have an email or isn't verified."}))).into_response();
    }

    if me_json.global_name.is_none() {
        me_json.global_name = Some(me_json.username.clone());
    }

    if me_json.avatar.is_none() {
        me_json.avatar = Some(format!("https://api.dicebear.com/7.x/thumbs/svg?seed={}", me_json.id));
    } else {
        me_json.avatar = Some(format!("https://cdn.discordapp.com/avatars/{}/{}.png", me_json.id, me_json.avatar.unwrap()));
    }

    let provider = Provider::Discord;

    // DISCORD ACCESS TOKEN - NOT JWT!!!
    let expires_at = match res_json.expires_in {
        Some(duration) => Some(Utc::now() + Duration::seconds(duration)),
        None => None, // treat as non-expiring, or set a conservative default
    };

    let userid: Uuid = match sqlx::query(r#"
    SELECT userid FROM users
    WHERE (email = $1) OR ("providerId" = $2)
    "#)
    .bind(&me_json.email)
    .bind(&me_json.id)
    .fetch_optional(&state)
    .await {
        Ok(Some(e)) => e.get("userid"),
        Ok(None) => uuid::Uuid::new_v4(),
        Err(e) => {
            println!("Error getting UUID from SQL: {}", e);
            return throw_internal_server_error().await;
        }
    };

    let _ = match sqlx::query(r#"
    INSERT INTO users (userid, email, username, "displayName", "pfpUrl", "createdAt", provider, "providerId", "accessToken", "refreshToken", "tokenExpiresAt")
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    ON CONFLICT (email)
    DO UPDATE SET
        "accessToken" = EXCLUDED."accessToken",
        "refreshToken" = EXCLUDED."refreshToken",
        "tokenExpiresAt" = EXCLUDED."tokenExpiresAt",
        provider = EXCLUDED.provider,
        "providerId" = EXCLUDED."providerId";
    "#)
    .bind(&userid)
    .bind(&me_json.email)
    .bind(&me_json.username)
    .bind(&me_json.global_name)
    .bind(&me_json.avatar)
    .bind(&now)
    .bind(&provider)
    .bind(&me_json.id)
    .bind(&res_json.access_token)
    .bind(&res_json.refresh_token)
    .bind(&expires_at)
    .execute(&state)
    .await {
        Ok(e) => e,
        Err(e) => {
            println!("Unable to create new user from Discord OAUTH: {}", e);
            return throw_internal_server_error().await;
        } 
    };

    // JWT!!

    let expiration = now.timestamp() + 60 * 60 * 24 * 7; // Token valid for 7 days
    let claims = Token {
        sub: userid.to_string(),
        exp: expiration as usize,
        iat: now.timestamp() as usize,
        username: me_json.username,
        provider: provider,
        provider_id: me_json.id
    };

    let key = match std::env::var("JWT_KEY") {
        Ok(jwt) => jwt,
        Err(e) => {
            println!("No JWT signing secret found: {}", e);
            return throw_internal_server_error().await;
        }
    };

    let token = match jsonwebtoken::encode(&Header::default(), &claims, &EncodingKey::from_secret(&key.as_ref())) {
        Ok(tok) => tok,
        Err(e) => {
            println!("JWT unable to be created: {}", e);
            return throw_internal_server_error().await;
        }
    };


    let redirect_uri = format!("https://accounts.betterseqta.org/auth/discord/callback?token={}", token);

    Redirect::to(&redirect_uri).into_response()
}