use axum::{extract::Request, http::{self, StatusCode}, middleware::Next, Json, response::IntoResponse};
use serde_json::json;

use jsonwebtoken;

use crate::types::{AuthError, Token};
use crate::responses::throw_internal_server_error;

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status_code,
            Json(json!({
                "status": self.status_code.as_u16().to_string(),
                "message": self.message
            }))
        ).into_response()
    }
}

fn forbidden(msg: &str) -> AuthError {
    AuthError {
        message: msg.into(),
        status_code: StatusCode::FORBIDDEN,
    }
}


pub async fn authorization_middleware(mut req: Request, next: Next) -> impl IntoResponse {
    let cookies = match req.headers().get(http::header::COOKIE).and_then(|h| h.to_str().ok()) {
        Some(c) => c,
        None => return forbidden("Empty cookies").into_response(),
    };

    let auth_cookie = match cookie::Cookie::split_parse(cookies)
        .flatten()
        .find(|c| c.name() == "auth_token") {
        Some(c) => c,
        None => return forbidden("No Auth cookie").into_response(),
    };

    let key = match std::env::var("JWT_KEY") {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "JWT key not found").into_response(),
    };

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true;

    let token = match jsonwebtoken::decode::<Token>(
        auth_cookie.value(),
        &jsonwebtoken::DecodingKey::from_secret(key.as_ref()),
        &validation,
    ) {
        Ok(t) => t,
        Err(_) => return forbidden("Invalid token").into_response(),
    };

    req.extensions_mut().insert(token.claims);

    next.run(req).await
}
