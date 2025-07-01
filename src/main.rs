use std::{sync::Arc, time::Duration, net::SocketAddr};

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
use crate::{api::api_router, statics::{initialize_env, initialize_regex}};

mod responses;
mod types;

mod statics;

use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};


#[tokio::main]
async fn main() {
    initialize_env();
    initialize_regex();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().pretty())
        .init();

    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(3)
            .burst_size(4)
            .finish()
            .unwrap(),
    );

    let governor_limiter = governor_conf.limiter().clone();
    let interval = Duration::from_secs(60);
    // a separate background task to clean up
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(interval);
            tracing::info!("rate limiting storage size: {}", governor_limiter.len());
            governor_limiter.retain_recent();
        }
    });

    // build our application with a single route
    let app = Router::new().nest("/api", api_router().await).layer(
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(GovernorLayer {
                config: governor_conf,
            })
    );

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}