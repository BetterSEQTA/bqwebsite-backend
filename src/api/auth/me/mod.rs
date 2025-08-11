use axum::{response::IntoResponse, Extension};
use crate::types::Token;

pub async fn me(Extension(token): Extension<Token>) -> impl IntoResponse {
    format!("{:?}", token)
}