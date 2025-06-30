use axum::{body::Body, http::{Response, StatusCode}, response::IntoResponse, Json };

use serde_json::{json};

pub async fn throw_internal_server_error() -> Response<Body> {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "status": 500,
            "message": "Internal server error"
        }))
    ).into_response()
}