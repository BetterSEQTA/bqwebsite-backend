use ::chrono::Utc;
use sqlx::{types::chrono, PgPool};

use axum::{body::Body, extract::State, http::{StatusCode}, response::{IntoResponse}, Json };
use uuid::Uuid;

use serde::{Serialize, Deserialize};
use serde_json::Value;

use argon2::{
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, Salt, SaltString
    },
    Argon2
};

use sha2::Sha256;
use hmac::{Hmac, Mac};

use jsonwebtoken::{ Header, EncodingKey };
use std::time::{SystemTime, UNIX_EPOCH};

use std::env;

use serde_json::json;

use crate::responses::throw_internal_server_error;

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

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    sub: String,
    exp: usize,
    iat: usize,
    username: String,
    email: String
}


pub async fn login(State(state): State<PgPool>, Json(payload): Json<Value>) -> impl IntoResponse {
    let email = match payload.get("email").and_then(|v| v.as_str()) {
        Some(e) => e,
        None => return (StatusCode::BAD_REQUEST, Json(json!({"status": 400, "message": "Missing email"}))).into_response(),
    };
    let password = match payload.get("password").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(json!({"status": 400, "message": "Missing password"}))).into_response(),
    };

    let user = match sqlx::query!(
        r#"
        SELECT
            password,
            userid,
            email,
            username
        FROM users
        WHERE email = $1
        "#,
        email
    )
    .fetch_optional(&state)
    .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return (StatusCode::UNAUTHORIZED, 
                            Json(json!({
                                "status": 401,
                                "message": "Invalid email or password"
                            })))
                    .into_response(),
        Err(e) => {
            println!("Database fetch error occurred: {}", e);
            return throw_internal_server_error();
        }
    };

    let argon2 = Argon2::default(); // Initialise argon2.


    let parsed_hash = match PasswordHash::new(&user.password) {
        Ok(hash) => hash,
        Err(e) => {
            println!("Error parsing hash: {}", e);
            return throw_internal_server_error();
        }
    };

    let pepper = match env::var("PEPPER") {
        Ok(pep) => pep,
        Err(e) => {
            println!("Pepper error occurred: {}", e);
            return throw_internal_server_error();
        }
    };

    let mut mac = match Hmac::<Sha256>::new_from_slice(&pepper.as_bytes()) {
        Ok(hmac_hash) => hmac_hash,
        Err(e) => {
            println!("Error occurred creating the HMAC hash in login: {}", e);
            return throw_internal_server_error();
        }
    };

    mac.update(password.as_bytes());
    let hmac_result = mac.finalize().into_bytes();

    match argon2.verify_password(&hmac_result, &parsed_hash) {
        Ok(_) => {

            let now = match SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    {
                        Ok(t) => t.as_secs() as usize,
                        Err(e) => {
                            println!("Time went backwards!: {}", e);
                            return throw_internal_server_error();
                        }
                    };
        
            let expiration = now + 60 * 60 * 24 * 7; // Token valid for 7 days
        

            let claims = Token {
                    sub: user.userid.to_string(),
                    exp: expiration,
                    iat: now,
                    username: user.username.to_string(),
                    email: user.email.to_string()
            };

            let key = match env::var("JWT_KEY") {
                Ok(jwt) => jwt,
                Err(e) => {
                    println!("No JWT signing secret found: {}", e);
                    return throw_internal_server_error();
                }
            };

            let token = match jsonwebtoken::encode(&Header::default(), &claims, &EncodingKey::from_secret(&key.as_ref())) {
                Ok(tok) => tok,
                Err(e) => {
                    println!("JWT unable to be created: {}", e);
                    return throw_internal_server_error();
                }
            };

            return (
                StatusCode::OK,
                Json(json!({"status": 200, "token": token}))
            ).into_response()
        }
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "status": 401,
                    "message": "Invalid email or password"
                }))
            ).into_response()
        }
    };
}