use axum::{
    routing::get,
    routing::post,
    Router,
};
use dotenvy::dotenv;

use std::sync::Arc;

use tower::{ ServiceBuilder };


mod auth;
mod health;

use sqlx::{postgres::PgPoolOptions, PgPool};
use std::env;



pub async fn api_router() -> Router {
    let _ = dotenv().ok();
    let postgres_connection = env::var("POSTGRES_URI").expect("No PostgreSQL uri found");

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&postgres_connection).await;

    let shared_db = pool.expect("Unable to create shared state");

    Router::new()
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::me))
        .route("/auth/register", post(auth::register))
        .route("/health", get(health::health))
        .layer(
            ServiceBuilder::new()
        )
        .with_state(shared_db)

}