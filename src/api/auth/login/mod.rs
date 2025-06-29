use ::chrono::Utc;
use sqlx::{postgres::{PgQueryResult, PgRow}, types::chrono, Executor, PgPool};

use axum::{extract::State, handler::Handler, http::StatusCode, Error, Json, response::{IntoResponse, Response}, body::Body };
use uuid::Uuid;

use serde::{Serialize, Deserialize};
use serde_json::Value;

use argon2::{
    password_hash::{
        rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, Salt, SaltString
    },
    Argon2
};

use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
use std::time::{SystemTime, Duration, UNIX_EPOCH};

use std::env;

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
    created_at: Option<chrono::DateTime<Utc>>,
    salt: Option<String>

}

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    sub: String,
    exp: usize,
    iat: usize,
    username: String,
    email: String
}


pub async fn login(State(state): State<PgPool>, Json(payload): Json<Value>) -> Response {
    let email = payload["email"].as_str().unwrap();
    let password = payload["password"].as_str().unwrap();
    let users = sqlx::query!(
        r#"
        SELECT
            password,
            salt,
            userid,
            email,
            username
        FROM users
        WHERE email = $1
        "#,
        email
    )
    .fetch_all(&state)
    .await
    .expect("Login malfunctioned");


    if users.iter().len() > 0 {
        let user = users.first().expect("Something went wrong. User doesn't exist??");

        let argon2 = Argon2::default();

        let parsed_hash = PasswordHash::new(&user.password).expect("Unable to parse stored password hash");

        match argon2.verify_password(&password.as_bytes(), &parsed_hash) {
            Ok(_) => {

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs() as usize;
        
                let expiration = now + 60 * 60 * 24 * 7; // Token valid for 7 days
        

                let claims = Token {
                    sub: user.userid.to_string(),
                    exp: expiration,
                    iat: now,
                    username: user.username.to_string(),
                    email: user.email.to_string()
                };

                let key = env::var("JWT_KEY").expect("No JWT signing secret found");

                let token = jsonwebtoken::encode(&Header::default(), &claims, &EncodingKey::from_secret(&key.as_ref())).expect("JWT unable to be created");
                return Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(Json(token).to_string()))
                    .unwrap()
            },
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::from(Json(String::from("Invalid email or password")).to_string()))
                    .unwrap()
            }
        };
    }

    
    Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::from(Json(String::from("Invalid email or password")).to_string()))
                    .unwrap()
}