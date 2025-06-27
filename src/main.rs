use axum::{
    routing::get,
    routing::post,
    Router,
    http::{ Method, HeaderValue }
};

use tower::{ ServiceBuilder };
use tower_http::{
    cors::{ CorsLayer },
    compression::{ CompressionLayer }
};

pub mod auth;

#[tokio::main]
async fn main() {
    let allowed_origin = "https://accounts.betterseqta.org"
        .parse::<HeaderValue>()
        .expect("Failed to parse allowed origin");

    let cors = CorsLayer::new().allow_origin(allowed_origin)
        .allow_methods(Method::POST);

    let compression = CompressionLayer::new().br(true).quality(tower_http::CompressionLevel::Fastest);

    // build our application with a single route
    let app = Router::new().route("/api/login", post(auth::login)).layer(
        ServiceBuilder::new()
            .layer(cors)
            .layer(compression),
    );

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}