use crate::db::Pool;
use crate::user::UserDTO;
use axum::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::response::Redirect;
use axum::RequestPartsExt;
use axum_extra::extract::CookieJar;
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

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // TODO: You have to read the auth cookie and verify the JWT to ensure the user is
        //       authenticated.
        let jar = parts
            .extract::<CookieJar>()
            .await
            .expect("Could not get CookieJar from request parts");
        let _jwt = jar.get("auth").ok_or(Redirect::to(REDIRECT_URL))?.value();

        let jwt_secret = std::env::var("JWT_SECRET_KEY").expect("JWT_SECRET_KEY not set");

        return match decode::<UserDTO>(&_jwt, &DecodingKey::from_secret(jwt_secret.as_ref()), &Validation::default()) {
            Ok(user) => Ok(user.claims),
            Err(_) => Err(Redirect::to(REDIRECT_URL)),
        }
    }
}
