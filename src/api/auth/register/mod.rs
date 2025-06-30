use ::chrono::{DateTime, Utc};
use sqlx::{PgPool};

use axum::{extract::State, http::{StatusCode}, response::{IntoResponse}, Json };
use uuid::{Uuid};

use serde_json::Value;

use hmac::{Hmac, Mac};
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher, SaltString
    },
    Argon2
};
use sha2::Sha256;

use std::time::{SystemTime};

use std::env;

use serde_json::json;

use crate::{responses::throw_internal_server_error, types::Provider};

use ammonia::clean;

const USERNAME_MIN_LEN: usize = 3;
const USERNAME_MAX_LEN: usize = 32;

const EMAIL_MIN_LEN: usize = 5;
const EMAIL_MAX_LEN: usize = 320;

const PASSWORD_MIN_LEN: usize = 8;
const PASSWORD_MAX_LEN: usize = 128;

pub async fn register(State(state): State<PgPool>, Json(payload): Json<Value>) -> impl IntoResponse {
    let email_regex = match regex::Regex::new(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)") {
        Ok(r) => r,
        Err(e) => {
            println!("Something went wrong with email regex!: {}", e);
            return throw_internal_server_error().await;
        }
    };


    let email = match payload.get("email").and_then(|v| v.as_str()) {
        Some(e) => {
            if (e.len() < EMAIL_MIN_LEN || e.len() > EMAIL_MAX_LEN) || !email_regex.is_match(e) {
            return (StatusCode::BAD_REQUEST, 
                    Json(json!({"status": 400, "message": "Email not between 5 and 320 characters or not formatted correctly."})))
                  .into_response();
            }
            e.to_lowercase()
        },
        None => return (StatusCode::BAD_REQUEST, Json(json!({"status": 400, "message": "Missing email"}))).into_response(),
    };

    let password = match payload.get("password").and_then(|v| v.as_str()) {
        Some(e) => {
            if e.len() < PASSWORD_MIN_LEN || e.len() > PASSWORD_MAX_LEN {
            return (StatusCode::BAD_REQUEST, 
                    Json(json!({"status": 400, "message": "Password not between 8 and 128 characters"})))
                  .into_response();
            }
            e
        },
        None => return (StatusCode::BAD_REQUEST, Json(json!({"status": 400, "message": "Missing password"}))).into_response(),
    };

    let username = match payload.get("username").and_then(|v| v.as_str()) {
        Some(e) => {
            let tex = clean(e);
            if tex.len() < USERNAME_MIN_LEN || tex.len() > USERNAME_MAX_LEN {
            return (StatusCode::BAD_REQUEST, 
                    Json(json!({"status": 400, "message": "Username not within 3 and 32 characters"})))
                  .into_response();
            }
            tex.to_lowercase()
        }
        None => return (StatusCode::BAD_REQUEST, Json(json!({"status": 400, "message": "Missing username"}))).into_response(),
    };

    let display_name = match payload.get("displayName").and_then(|v| v.as_str()) {
        Some(e) => {
            let tex = clean(e);
            if tex.len() < USERNAME_MIN_LEN || tex.len() > USERNAME_MAX_LEN {
            return (StatusCode::BAD_REQUEST, 
                    Json(json!({"status": 400, "message": "Display name not within 3 and 32 characters"})))
                  .into_response();
            }
            tex
        },
        None => username.clone()
    };

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let pepper = match env::var("PEPPER") {
        Ok(pep) => pep,
        Err(e) => {
            println!("Pepper error occurred: {}", e);
            return throw_internal_server_error().await;
        }
    };

    let mut mac = match Hmac::<Sha256>::new_from_slice(&pepper.as_bytes()) {
        Ok(hmac_hash) => hmac_hash,
        Err(e) => {
            println!("Error occurred creating the HMAC hash in login: {}", e);
            return throw_internal_server_error().await;
        }
    };

    mac.update(password.as_bytes());
    let hmac_result = mac.finalize().into_bytes();

    let hash = match argon2.hash_password(&hmac_result, &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            println!("Error occurred when argon was generating a hash: {}", e);
            return throw_internal_server_error().await;
        }
    };

    let user_id = Uuid::new_v4();
    let created_at: DateTime<Utc> = SystemTime::now().into();

    let provider = Provider::Credentials;

    match sqlx::query(
        r#"
        INSERT INTO users (email, username, password, "displayName", userid, "createdAt", provider, "providerId")
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT DO NOTHING;
        "#
    ).bind(&email)
    .bind(&username)
    .bind(&hash)
    .bind(&display_name)
    .bind(&user_id)
    .bind(&created_at)
    .bind(&provider)
    .bind(&user_id)
    .execute(&state)
    .await {
        Ok(_) => return (StatusCode::OK, Json(json!({"status": 200, "message": "If this email or username is available, an account has been created"}))).into_response(),
        Err(e) => {
            println!("Error creating a new user in db: {}", e);
            return throw_internal_server_error().await;
        }

    }
}