use crate::db::{DbConn, user_exists, save_user, verify_user, get_user};
use crate::models::{
    AppState, LoginRequest, OAuthRedirect, PasswordUpdateRequest, RegisterRequest,
};
use crate::user::{AuthenticationMethod::Password, User, UserDTO};
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
use diesel::PgJsonbExpressionMethods;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use jsonwebtoken::{encode, Header, EncodingKey, Algorithm, TokenData};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;


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
    println!("User logged in !");
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
        .body(format!("Please follow the link to verify your email address: http://localhost:8000/verify_email/{}", urlencoding::encode(&session_id)))
        .unwrap();

    let creds = Credentials::new("bd51a3078e245f".to_string(), "89a416b171b64d".to_string());

    // Open a remote connection to gmail
    let mailer = SmtpTransport::builder_dangerous("smtp.mailtrap.io")
        .credentials(creds)
        .port(2525)
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
    // TODO: This function is used to authenticate a user with Google's OAuth2 service.
    //       We want to use a PKCE authentication flow, you will have to generate a
    //       random challenge and a CSRF token. In order to get the email address of
    //       the user, use the following scope: https://www.googleapis.com/auth/userinfo.email
    //       Use Redirect::to(url) to redirect the user to Google's authentication form.

    // let client = crate::oauth::OAUTH_CLIENT.todo();

    // If you need to store data between requests, you may use the session_store. You need to first
    // create a new Session and store the variables. Then, you add the session to the session_store
    // to get a session_id. You then store the session_id in a cookie.
    Ok((jar, Redirect::to("myurl")))
}

/// Endpoint called after a successful OAuth login.
/// GET /_oauth?state=x&code=y
async fn oauth_redirect(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
    _conn: DbConn,
    _params: Query<OAuthRedirect>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // TODO: The user should be redirected to this page automatically after a successful login.
    //       You will need to verify the CSRF token and ensure the authorization code is valid
    //       by interacting with Google's OAuth2 API (use an async request!). Once everything
    //       was verified, get the email address with the provided function (get_oauth_email)
    //       and create a JWT for the user.

    // If you need to recover data between requests, you may use the session_store to load a session
    // based on a session_id.

    // Once the OAuth user is authenticated, create the user in the DB and add a JWT cookie
    // let jar = add_auth_cookie(jar, &user_dto).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok((jar, Redirect::to("/home")))
}

/// Endpoint handling login
/// POST /password_update
/// BODY { "old_password": "pass", "new_password": "pass" }
async fn password_update(
    _conn: DbConn,
    _user: UserDTO,
    Json(_update): Json<PasswordUpdateRequest>,
) -> Result<AuthResult, Response> {
    // TODO: Implement the password update function.
    Ok(AuthResult::Success)
}

/// Endpoint handling the logout logic
/// GET /logout
async fn logout(jar: CookieJar) -> impl IntoResponse {
    let new_jar = jar.remove(Cookie::named("auth"));
    (new_jar, Redirect::to("/home"))
}

#[allow(dead_code)]
fn add_auth_cookie(jar: CookieJar, _user: &UserDTO) -> Result<CookieJar, Box<dyn Error>> {
    let expires_in = Duration::weeks(1);
    let expires = OffsetDateTime::now_utc() + expires_in;

    let jwt = encode(
        &Header::default(),
        _user,
        &EncodingKey::from_secret("secret".as_ref())
    )?;

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
