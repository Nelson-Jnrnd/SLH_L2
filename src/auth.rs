use std::env;
use crate::db::Pool;
use crate::user::UserDTO;
use axum::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::response::Redirect;
use axum::RequestPartsExt;
use axum_extra::extract::CookieJar;
use jsonwebtoken::decode;
use jsonwebtoken::errors::Error as JWTError;
use serde::Deserialize;
use jsonwebtoken::{decode, DecodingKey, Validation};


const REDIRECT_URL: &str = "/home";

/// Retrieves a UserDTO from request parts if a user is currently authenticated.
#[async_trait]
impl<S> FromRequestParts<S> for UserDTO
    where
        Pool: FromRef<S>,
        S: Send + Sync,
{
    type Rejection = Redirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jar = parts
            .extract::<CookieJar>()
            .await
            .expect("Could not get CookieJar from request parts");
        let jwt = jar.get("auth").ok_or(Redirect::to(REDIRECT_URL))?.value();

        let secret = env::var("JWT_SECRET").expect("Could not get JWT_SECRET from ENV");
        let result = jsonwebtoken::decode::<UserDTO>(
            jwt,
            &DecodingKey::from_secret(secret.as_ref()),
            &Validation::default(),
        );

        match result {
            Ok(token) => Ok(token.claims),
            Err(e) => {
                println!("Error: {}", e);
                Err(Redirect::to(REDIRECT_URL))
            }
        }
    }
}
