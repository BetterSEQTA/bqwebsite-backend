use axum::{
    handler::Handler, middleware, routing::{get, post}, Router
};

use tower::{ ServiceBuilder };


mod auth;
mod health;

use sqlx::{postgres::PgPoolOptions};
use std::env;

use crate::middleware::{authorization_middleware};



pub async fn api_router() -> Router {

    let postgres_connection = env::var("DATABASE_URL").expect("No PostgreSQL uri found");

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&postgres_connection).await;

    let shared_db = pool.expect("Unable to create shared state");

    Router::new()
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::me)
            .layer(ServiceBuilder::new()
                .layer(
                    middleware::from_fn(authorization_middleware)
                )
        )
        )
        .route("/health", get(health::health))
        .route("/auth/oauth/discord", get(auth::oauth::discord::define_event_handler))
        .route("/auth/callback/discord", get(auth::callback::discord::exchange_code))
        .layer(
            ServiceBuilder::new()
        )
        .with_state(shared_db)

}