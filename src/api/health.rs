use axum::Json;
use uuid::Uuid;
use serde::Serialize;

#[derive(Serialize)]
pub struct Health {
    id: Uuid,
    date_time: std::time::SystemTime,
    status: String,
}

pub async fn health() -> Json<Health> {
    let health_data = Health {
        id: Uuid::new_v4(),
        date_time: std::time::SystemTime::now(),
        status: "ok".to_string()
    };
    Json(health_data)
}