// TODO CHANGE ALL OF THIS SO THAT SESSIONS HAVE THEIR OWN TABLE
// CHANGE SQL QUERIES NEAR THE END.


use axum::{extract::{self, State, connect_info::{ConnectInfo, Connected}}, http::{StatusCode, HeaderMap, HeaderValue}, response::{IntoResponse}, Json};
use ::chrono::{DateTime, Duration, Utc};
use sqlx::{types::chrono, PgPool, Row};

use reqwest::{header, redirect::Policy};

use serde_json::json;
use uuid::Uuid;

use jsonwebtoken::{ Header, EncodingKey };

use crate::statics::USERNAME_REGEX;


use crate::{responses::throw_internal_server_error, types::{DiscordAccessTokenResponse, DiscordCallbackQuery, DiscordUser, Provider, Token, MyConnectionInfo}};

pub async fn exchange_code(State(state): State<PgPool>, extract::Query(query): extract::Query<DiscordCallbackQuery>) -> impl IntoResponse {
    let query_state = query.state;
    let query_code = query.code;

    let mut tx = match state.begin().await {
        Ok(e) => e,
        Err(e) => {
            println!("Error creating transaction handler in OAUTH: {}", e);
            return throw_internal_server_error().await;
        }
    };

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
    WHERE state = $1
    FOR UPDATE;
    "#)
    .bind(&query_state)
    .fetch_optional(&mut *tx)
    .await;

    let created_at: DateTime<Utc> = match &db_state {
        Ok(Some(record)) => record.get("created_at"),
        Ok(None) => {
            let _ = match tx.rollback().await {
                Ok(e) => e,
                Err(e) => { 
                    println!("Error rolling back transaction: {}", e); 
                    return throw_internal_server_error().await; 
                }
            };
            let _ = 
            return (StatusCode::UNAUTHORIZED, "Invalid state token").into_response();
        },
        Err(e) => {
            println!("Error getting creation date for state token in callback: {}", e);
            let _ = match tx.rollback().await {
                Ok(e) => e,
                Err(e) => { 
                    println!("Error rolling back transaction: {}", e); 
                    return throw_internal_server_error().await; 
                }
            };
            return throw_internal_server_error().await;
        }
    };

    let now = chrono::Utc::now();
    if now.signed_duration_since(&created_at).num_minutes() > 15 {
        let _ = match tx.rollback().await {
                Ok(e) => e,
                Err(e) => { 
                    println!("Error rolling back transaction: {}", e); 
                    return throw_internal_server_error().await; 
                }
        };
        return (StatusCode::UNAUTHORIZED, "State token expired").into_response();
    }

    let _ = match sqlx::query(r#"DELETE FROM state WHERE state = $1"#)
    .bind(&query_state)
    .execute(&mut *tx)
    .await {
        Ok(e) => e,
        Err(e) => {
            println!("Error deleting valid state: {}", e);
            return throw_internal_server_error().await;
        }
    };

    let _ = match tx.commit().await {
        Ok(e) => e,
        Err(e) => {
            println!("Error finalising Postgres transaction: {}", e);
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

    let params = [("grant_type", "authorization_code"), ("code", &query_code), ("redirect_uri", &redirect_uri)];
    let client = match reqwest::Client::builder().redirect(Policy::none()).build() {
        Ok(e) => e,
        Err(e) => {
            println!("Error setting reqwest redirect policy: {}", e);
            return throw_internal_server_error().await;
        }
    };

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

    let email = match me_json.email {
        Some(e) => e,
        None => return (StatusCode::BAD_REQUEST, Json(json!({"status": "400", "message": "Your Discord account doesn't have an email or isn't verified."}))).into_response(),
    };

    if me_json.global_name.is_none() {
        me_json.global_name = Some(me_json.username.clone());
    }

    if !USERNAME_REGEX.get().unwrap().is_match(&me_json.username) {
        return (StatusCode::BAD_REQUEST, Json(json!({"status": "400", "message": "Invalid username"}))).into_response()
    }

    me_json.avatar = Some(match me_json.avatar {
        None => format!("https://api.dicebear.com/7.x/thumbs/svg?seed={}", me_json.id),
        Some(avatar) => format!("https://cdn.discordapp.com/avatars/{}/{}.png", me_json.id, avatar)
    });

    let provider = Provider::Discord;

    // DISCORD ACCESS TOKEN - NOT JWT!!!
    let expires_at = match res_json.expires_in {
        Some(duration) => Some(Utc::now() + Duration::seconds(duration)),
        None => None, // treat as non-expiring, or set a conservative default
    };

    let mut user_tx = match state.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            println!("Error creating transaction for user operations: {}", e);
            return throw_internal_server_error().await;
        }
    };

    let userid: Uuid = match sqlx::query(r#"
    SELECT userid FROM users
    WHERE (email = $1)
    FOR UPDATE;
    "#)
    .bind(&email)
    .bind(&me_json.id)
    .fetch_optional(&mut *user_tx)
    .await {
        Ok(Some(e)) => e.get("userid"),
        Ok(None) => uuid::Uuid::new_v4(),
        Err(e) => {
            let _ = match user_tx.rollback().await {
                Ok(e) => e,
                Err(e) => { 
                    println!("Error rolling back transaction: {}", e); 
                    return throw_internal_server_error().await; 
                }
            };
            println!("Error getting UUID from SQL: {}", e);
            return throw_internal_server_error().await;
        }
    };

    let _ = match sqlx::query(r#"
    INSERT INTO users (userid, email, username, "displayName", "pfpUrl", "createdAt")
    VALUES ($1, $2, $3, $4, $5, $6)
    ON CONFLICT DO NOTHING;
    "#)
    .bind(&userid)
    .bind(&email)
    .bind(&me_json.username)
    .bind(&me_json.global_name)
    .bind(&me_json.avatar)
    .bind(&now)
    .execute(&mut *user_tx)
    .await {
        Ok(e) => e,
        Err(e) => {
            println!("Unable to create new user from Discord OAUTH: {}", e);
            let _ = match user_tx.rollback().await {
                Ok(e) => e,
                Err(e) => { 
                    println!("Error rolling back transaction: {}", e); 
                    return throw_internal_server_error().await; 
                }
            };
            return throw_internal_server_error().await;
        } 
    };

    let session_id = uuid::Uuid::new_v4();

    let _ = match sqlx::query(r#"
    INSERT INTO sessions (session_id, issued_at, expires_at, provider, provider_id, access_token, refresh_token, token_expires_at, user_id)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    ON CONFLICT DO NOTHING;
    "#)
    .bind(&session_id)
    .bind(&now)
    .bind(Utc::now() + Duration::minutes(44640))
    .bind(&provider)
    .bind(&me_json.id)
    .bind(&res_json.access_token)
    .bind(&res_json.refresh_token)
    .bind(&expires_at)
    .bind(&userid)
    .execute(&mut *user_tx)
    .await {
        Ok(e) => e,
        Err(e) => {
            println!("Unable to create new session on DB: {}", e);
            return throw_internal_server_error().await;
        }
    };

    let _ = match user_tx.commit().await {
        Ok(e) => e,
        Err(e) => {
            println!("Error finalising Postgres transaction: {}", e);
            return throw_internal_server_error().await;
        }
    };

    // JWT!!

    let expiration = now.timestamp() + 60 * 60 * 24 * 31; // Token valid for 31 days
    let claims = Token {
        sub: session_id.to_string(),
        exp: expiration as usize,
        iat: now.timestamp() as usize,
        toktype: String::from("auth")
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

    let redirect_uri = match std::env::var("CALLBACK_URI_DISCORD") {
        Ok(e) => e,
        Err(_) => {
            println!("Error getting callback URI");
            return throw_internal_server_error().await;
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE, 
        format!("auth_token={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800", token)
            .parse()
            .unwrap_or_else(|_| {
                println!("Error parsing header value");
                HeaderValue::from_static("")
            })
    );
    headers.insert(header::LOCATION, redirect_uri.parse().unwrap());

    (StatusCode::FOUND, headers, "").into_response()
}