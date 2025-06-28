use axum::{
    routing::get,
    routing::post,
    Router,
};

use tower::{ ServiceBuilder };

mod auth;

pub fn api_router() -> Router {
    Router::new()
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::me))
        .route("/auth/register", post(auth::register))
        .layer(
            ServiceBuilder::new()
        )

}