use sqlx::{postgres::{PgQueryResult, PgRow}, Executor, PgPool};

use axum::{extract::State, handler::Handler, http::StatusCode, Error, Json, response::{IntoResponse, Response}};

use std::sync::Arc;


pub async fn login(State(state): State<PgPool>) -> String {
    /*let result = sqlx::query("SELECT * FROM bqplus")
        .fetch_all(&state)
        .await
        .expect("Login malfunctioned");
    Json(result)*/
    "hi".to_string()
}