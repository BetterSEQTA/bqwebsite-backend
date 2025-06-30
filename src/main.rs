use axum::{
    Router,
};


use tower_http::trace::{TraceLayer};
use tower::ServiceBuilder;

use tracing_subscriber::{
    layer::SubscriberExt, 
    util::SubscriberInitExt
};

mod api;
use crate::api::api_router;

mod responses;
mod types;

#[tokio::main]
async fn main() {

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().pretty())
        .init();

    // build our application with a single route
    let app = Router::new().nest("/api", api_router().await).layer(
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
    );

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}