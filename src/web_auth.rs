use std::env;
use std::borrow::Borrow;
use crate::db::{DbConn, user_exists, save_user, verify_user, get_user, update_password};
use crate::models::{
    AppState, LoginRequest, OAuthRedirect, PasswordUpdateRequest, RegisterRequest,
};
use crate::user::{AuthenticationMethod::Password, AuthenticationMethod::OAuth, User, UserDTO};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use axum_sessions::async_session::{MemoryStore, Session, SessionStore};
use serde_json::json;
use std::error::Error;
use time::{Duration, OffsetDateTime};
use axum_extra::handler::HandlerCallWithExtractors;
use diesel::{BoolExpressionMethods, PgJsonbExpressionMethods};
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use jsonwebtoken::{encode, Header, EncodingKey, Algorithm, TokenData};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use hyper::{Body, Method, Request, Uri};
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, Scope, TokenResponse};
use oauth2::reqwest::async_http_client;
use reqwest::Client;
use serde_json::Value;
use serde::{Deserialize, Serialize};
use crate::oauth::get_google_oauth_email;


/// Declares the different endpoints
/// state is used to pass common structs to the endpoints
pub fn stage(state: AppState) -> Router {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/oauth/google", get(google_oauth))
        .route("/_oauth", get(oauth_redirect))
        .route("/password_update", post(password_update))
        .route("/logout", get(logout))
        .route("/verify_email/:token", get(verify_email))
        .with_state(state)
}

/// Endpoint handling login
/// POST /login
/// BODY { "login_email": "email", "login_password": "password" }
async fn login(
    mut _conn: DbConn,
    jar: CookieJar,
    Json(login): Json<LoginRequest>,
) -> Result<(CookieJar, AuthResult), Response> {

    let email = login.login_email.to_lowercase();
    let password = login.login_password;

    // check if the user exists in the db
    let user = match get_user(&mut _conn, email.as_str()) {
        Ok(user_dto) => user_dto,
        Err(_) => return Err(AuthResult::Error("Invalid credentials".to_string()).into_response()),
    };

    // check if the password is correct if the user is using the password authentication method
    if user.get_auth_method() == Password {
        // TODO check if the password is correct using Argon2
        let hash = match PasswordHash::new(&user.password.as_str()) {
            Ok(hash) => hash,
            Err(_) => return Err(AuthResult::Error("Saved Password is invalid".to_string()).into_response()),
        };
        Argon2::default().verify_password(password.as_bytes(), &hash).or(Err(AuthResult::Error("Invalid credentials".to_string())));
    }

    // check if the email is verified
    if !user.email_verified {
        return Err(AuthResult::Error("Email not verified".to_string()).into_response());
    }

    // authenticate the user by adding a JWT cookie in the cookie jar
    let jar = add_auth_cookie(jar, &user.to_dto())
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;
    Ok((jar, AuthResult::Success))
}

/// Endpoint used to register a new account
/// POST /register
/// BODY { "register_email": "email", "register_password": "password", "register_password2": "password" }
async fn register(
    mut conn: DbConn,
    State(session_store): State<MemoryStore>,
    Json(register): Json<RegisterRequest>,
) -> Result<AuthResult, Response> {
    let email = register.register_email.to_lowercase(); // Make sure the email is lowercase to avoid duplicates
    let password = register.register_password;

    // check if the email already exists in the db TODO uncomment
    match user_exists(&mut conn, email.as_str()) {
        Ok(_) => return Err(AuthResult::Error("Email already exists".to_string()).into_response()),
        Err(_) => {},
    }

    // check if the password length is within the allowed range
    if password.len() < 8 || password.len() > 64 {
        return Err(AuthResult::Error("Password must be between 8 and 64 characters".to_string()).into_response());
    }

    // check if the password is strong enough using zxcvbn
    let password_strength = zxcvbn::zxcvbn(password.as_str(), &[]).unwrap();
    if password_strength.score() < 3 {
        return Err(AuthResult::Error("Password is not strong enough".to_string()).into_response());
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt).unwrap().to_string();

    // create a new user
    let user = User::new(email.as_str(), hash.as_str(), Password, false);
    match save_user(&mut conn, user) {
        Ok(_) => {},
        Err(_) => return Err(AuthResult::Error("Could not save user".to_string()).into_response()),
    }

    // create a new session to store the verification status
    let mut session = Session::new();
    session.insert("email", email.clone());
    session.insert("verification_status", "pending");

    // add the session to the session store
    let session_id = match session_store.store_session(session).await {
        Ok(Some(id)) => id,
        _ => return Err(AuthResult::Error("Could not store session".to_string()).into_response()),
    };

    // send the verification link to the user's email
    // use your preferred email library here

    let mail = Message::builder()
        .from("no-reply@example.com".parse().unwrap())
        .to(
            format!("{} <{}>", email.split("@").collect::<Vec<_>>()[0], email)
                .parse()
                .unwrap())
        .subject("Verify your email address")
        .body(format!("Here is your link my friend ! : http://localhost:8000/verify_email/{}", urlencoding::encode(&session_id)))
        .unwrap();

    let username = std::env::var("MAILER_USERNAME")
        .expect("MAILER_USERNAME must be set");
    let password = std::env::var("MAILER_PASSWORD")
        .expect("MAILER_PASSWORD must be set");
    let host = std::env::var("MAILER_HOST")
        .expect("MAILER_HOST must be set");
    let port = std::env::var("MAILER_PORT")
        .expect("MAILER_PORT must be set")
        .parse::<u16>()
        .expect("MAILER_PORT must be a valid port number");

    let creds = Credentials::new(username, password);

    // Open a remote connection to gmail
    let mailer = SmtpTransport::builder_dangerous(host)
        .credentials(creds)
        .port(port)
        .build();

    // Send the email
    match mailer.send(&mail) {
        Ok(_) => println!("Email sent successfully!"),
        Err(e) => panic!("Could not send email: {:?}", e),
    }

    Ok(AuthResult::Success)
}

// TODO: Create the endpoint for the email verification function.
/// Endpoint for email verification
async fn verify_email(
    mut conn: DbConn,
    State(session_store): State<MemoryStore>,
    Path(token): Path<String>,
) -> Result<Redirect, Response> {
    let decoded_token = urlencoding::decode(&token).expect("UTF-8");
    let session_id = decoded_token.to_string();
    let session = match session_store.load_session(session_id).await {
        Ok(Some(session)) => session,
        _ => return Err(AuthResult::Error("Could not get session".to_string()).into_response()),
    };

    let email: String = match session.get::<String>("email") {
        Some(email) => email.to_string(),
        _ => return Err(AuthResult::Error("Session does not contain email".to_string()).into_response()),
    };

    let verification_status: String = match session.get::<String>("verification_status") {
        Some(verification_status) => verification_status.to_string(),
        _ => return Err(AuthResult::Error("Session does not contain verification status".to_string()).into_response()),
    };

    if verification_status != "pending" {
        return Err(AuthResult::Error("Email already verified".to_string()).into_response());
    }

    match verify_user(&mut conn, email.as_str()) {
        Ok(_) => {
            session_store.destroy_session(session);
            return Ok(Redirect::to("/login"));
        },
        Err(_) => return Err(AuthResult::Error("Could not update user".to_string()).into_response()),
    }
}

/// Endpoint used for the first OAuth step
/// GET /oauth/google
async fn google_oauth(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    let client = crate::oauth::OAUTH_CLIENT.clone();

    // Generate a random challenge
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();

    // Build the URL for the Google OAuth form
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(challenge)
        .add_scope(Scope::new("email".to_string()))
        .url();

    // Store the challenge and CSRF token in the session
    let mut session = Session::new();
    session.insert("verifier", verifier);
    session.insert("csrf_token", csrf_token);

    // Add the session to the session store and get a session id
    let session_id = match _session_store.store_session(session).await {
        Ok(Some(id)) => id,
        _ => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let env_expriation_time_hours = env::var("JWT_EXPIRATION_TIME_HOURS")
        .expect("JWT_EXPIRATION_TIME_HOURS must be set")
        .parse::<i64>()
        .expect("JWT_EXPIRATION_TIME_HOURS must be an integer");

    // Store the session id in a cookie
    // Redirect the user to the Google OAuth form
    Ok((jar.add(Cookie::build("session_id", session_id)
        .path("/")
        .expires(OffsetDateTime::now_utc()+ Duration::hours(env_expriation_time_hours))
        .secure(true)
        .http_only(true)
        .finish()), Redirect::to(auth_url.as_str())))
}

// Google user info
#[derive(Serialize, Deserialize)]
struct GoogleUserInfo {
    id: String,
    email: String,
    verified_email: bool,
    picture: String,
}

/// Endpoint called after a successful OAuth login.
/// GET /_oauth?state=x&code=y
async fn oauth_redirect(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
    mut _conn: DbConn,
    _params: Query<OAuthRedirect>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // Retrieve the session_id cookie
    let session_id_cookie = jar.get("session_id").ok_or(StatusCode::BAD_REQUEST)?;

    // Retrieve the session from the session store
    let session =
        _session_store.load_session(session_id_cookie.value().to_string())
            .await.or(Err(StatusCode::UNAUTHORIZED))?.ok_or(StatusCode::UNAUTHORIZED)?;

    // Retrieve the pkce_verifier from the session
    let verifier = session.get("verifier").ok_or(StatusCode::UNAUTHORIZED)?;

    // Exchange the code for an access token
    let token_result =
        crate::oauth::OAUTH_CLIENT
            .exchange_code(AuthorizationCode::new(_params.code.to_string()))
            .set_pkce_verifier(verifier)
            .request_async(async_http_client).await.or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;


    // Retrieve the email address from the token result
    let email = get_google_oauth_email(&token_result).await.or(Err(StatusCode::UNAUTHORIZED))?;

    // Check if the user exists in the database
    let user_dto = match get_user(&mut _conn, email.clone().as_str()) {
        Ok(user) => {
            if user.get_auth_method() != OAuth {
                return Err(StatusCode::UNAUTHORIZED);
            }
            user.to_dto()
        },
        Err(_) => {
            // If the user does not exist, create a new user
            let user = User::new(email.as_str(), "", OAuth, true);
            let user_dto = user.to_dto();
            save_user(&mut _conn, user).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
            user_dto
        },
    };

    // Redirect the user to the home page
    Ok((add_auth_cookie(jar, &user_dto).or(Err(StatusCode::INTERNAL_SERVER_ERROR)).unwrap(), Redirect::to("/home")))
}

/// Endpoint handling login
/// POST /password_update
/// BODY { "old_password": "pass", "new_password": "pass" }
async fn password_update(
    mut _conn: DbConn,
    _user: UserDTO,
    Json(_update): Json<PasswordUpdateRequest>,
) -> Result<AuthResult, Response> {

    if _update.old_password == _update.new_password {
        return Err(AuthResult::Error("New password must be different from old password".to_string()).into_response());
    }

    let user = get_user(&mut _conn, _user.email.as_str()).or(Err(AuthResult::Error("Could not find user".to_string()).into_response()))?;

    if user.get_auth_method() != Password {
        return Err(AuthResult::Error("User does not have a password".to_string()).into_response());
    }

    let hash = match PasswordHash::new(&user.password.as_str()) {
        Ok(hash) => hash,
        Err(_) => return Err(AuthResult::Error("Saved Password is invalid".to_string()).into_response()),
    };
    Argon2::default().verify_password(_update.old_password.as_bytes(), &hash).or(Err(AuthResult::Error("Invalid credentials".to_string())));

    // check if the password length is within the allowed range
    if _update.new_password.len() < 8 || _update.new_password.len() > 64 {
        return Err(AuthResult::Error("Password must be between 8 and 64 characters".to_string()).into_response());
    }

    // check if the password is strong enough using zxcvbn
    let password_strength = zxcvbn::zxcvbn(_update.new_password.as_str(), &[]).unwrap();
    if password_strength.score() < 3 {
        return Err(AuthResult::Error("Password is not strong enough".to_string()).into_response());
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(_update.new_password.as_bytes(), &salt).unwrap().to_string();


    match update_password(&mut _conn, &_user.email, &hash) {
        Ok(_) => Ok(AuthResult::Success),
        Err(_) => Err(AuthResult::Error("Could not update password".to_string()).into_response()),
    }
}

/// Endpoint handling the logout logic
/// GET /logout
async fn logout(jar: CookieJar) -> impl IntoResponse {
    let new_jar = jar.remove(Cookie::named("auth"));
    (new_jar, Redirect::to("/home"))
}

#[allow(dead_code)]
fn add_auth_cookie(jar: CookieJar, _user: &UserDTO) -> Result<CookieJar, Box<dyn Error>> {

    let jwt_secret = env::var("JWT_SECRET_KEY").unwrap();

    let jwt = encode(
        &Header::default(),
        _user,
        &EncodingKey::from_secret(jwt_secret.as_ref())
    )?;

    let env_expriation_time_hours = env::var("JWT_EXPIRATION_TIME_HOURS")
        .expect("JWT_EXPIRATION_TIME_HOURS must be set")
        .parse::<i64>()
        .expect("JWT_EXPIRATION_TIME_HOURS must be an integer");
    let expires_in = Duration::days(env_expriation_time_hours);
    let expires = OffsetDateTime::now_utc() + expires_in;

    Ok(jar.add(Cookie::build("auth", jwt)
        .path("/")
        .expires(expires)
        .secure(true)
        .http_only(true)
        .finish())
    )
}

enum AuthResult {
    Success,
    Error(String),
}

/// Returns a status code and a JSON payload based on the value of the enum
impl IntoResponse for AuthResult {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Success => (StatusCode::OK, json!({"res":"Success"})),
            Self::Error(reason) => (StatusCode::INTERNAL_SERVER_ERROR, json!({"res": format!("error {}", reason)})),
        };
        (status, Json(message)).into_response()
    }
}
