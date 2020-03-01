use deadpool_postgres::{Client, Pool};
use lazy_static::*;
use regex::Regex;
use warp::{Filter, Rejection};
use warp::http::StatusCode;

use std::convert::Infallible;

lazy_static! {
    static ref TOKEN_SECRET_REGEX: Regex = Regex::new("^[a-fA-F0-9]{64}$").unwrap();
    static ref TOKEN_ID_REGEX: Regex = Regex::new("^[a-fA-F0-9]{32}$").unwrap();
}

#[derive(serde_derive::Deserialize)]
struct TokenSpecification {
    email: String,
    password: String,
    lifetime: String,
}

#[derive(serde_derive::Serialize)]
struct NewToken {
    id: String,
    secret: String,
    user_id: i32,
    lifetime: String,
    created: i32,
    last_active: i32,
}

#[derive(serde_derive::Serialize)]
struct JsonError {
    error: &'static str,
}

async fn post_tokens(spec: TokenSpecification, db: Client) -> Result<impl warp::Reply, Infallible> {
    let lifetime = spec.lifetime;

    if lifetime != "until-idle"
        && lifetime != "remember-me"
        && lifetime != "no-expiration"
    {
        return Ok(warp::reply::with_status(warp::reply::json(&JsonError {
            error: "'lifetime' must be 'until-idle', 'remember-me', or 'no-expiration'"
        }), StatusCode::BAD_REQUEST))
    }

    // get user record for the e-mail
    let rows = db
        .query(
            "SELECT id, password FROM identity WHERE email = $1",
            &[&spec.email],
        )
        .await
        .unwrap();
    if rows.len() != 1 {
        return Ok(warp::reply::with_status(warp::reply::json(&JsonError {
            error: "email not found or password invalid"
        }), StatusCode::BAD_REQUEST))
    }
    let user = rows.get(0).unwrap();

    // verify the password
    let password_hash: String = user.get("password");
    let matches = argon2::verify_encoded(&password_hash, &spec.password.as_bytes()).unwrap();
    if !matches {
        return Ok(warp::reply::with_status(warp::reply::json(&JsonError {
            error: "email not found or password invalid"
        }), StatusCode::BAD_REQUEST))
    }

    // create a token
    let user_id: i32 = user.get("id");
    let token_id = format!("{:0>32x}", rand::random::<u128>());
    let token_secret = format!(
        "{:0>32x}{:0>32x}",
        rand::random::<u128>(),
        rand::random::<u128>()
    );
    let rows = db
        .query(
            "INSERT INTO token VALUES ($1, $2, $3, $4, now(), now()) \
            RETURNING cast(extract(epoch from created) as integer) created, \
                      cast(extract(epoch from last_active) as integer) last_active",
            &[&token_id, &user_id, &token_secret, &lifetime],
        )
        .await
        .unwrap();

    let token = rows.get(0).unwrap();

    Ok(warp::reply::with_status(warp::reply::json(&NewToken {
        id: token_id,
        secret: token_secret,
        user_id,
        created: token.get("created"),
        last_active: token.get("last_active"),
        lifetime: lifetime.to_string(),
    }), StatusCode::OK))
}

async fn get_tokens(token: Token, db: Client) -> Result<&'static str, Infallible> {
    Ok("GET tokens\n")
}

async fn get_tokens_id(id: String, token: Token, db: Client) -> Result<String, Rejection> {
    Ok(format!("GET tokens_id {}\n", id))
}

async fn delete_tokens_id(id: String, token: Token, db: Client) -> Result<String, Infallible> {
    Ok(format!("DELETE tokens_id {}\n", id))
}

fn path_token_id() -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::path!(String).and_then(|id: String| async move {
        if !TOKEN_ID_REGEX.is_match(&id) {
            return Err(warp::reject::not_found())
        }

        Ok(id)
    })
}

struct Token {
    id: String,
    user_id: i32,
}

fn with_token(pool: Pool) -> impl Filter<Extract = (Token, ), Error = Rejection> + Clone {
    warp::cookie("token").and(with_db(pool)).and_then(|token_secret: String, db: Client| async move {
        if !TOKEN_SECRET_REGEX.is_match(&token_secret) {
            return Err(warp::reject::custom(TokenFormatRejection))
        }

        let rows = db
            .query(
                "SELECT id, identity_id FROM token_active WHERE secret = $1",
                &[&token_secret],
            )
            .await
            .unwrap();
        if rows.len() != 1 {
            return Err(warp::reject::custom(UnauthorizedRejection))
        }
        let token = rows.get(0).unwrap();
        let id: String = token.get("id");
        let user_id: i32 = token.get("identity_id");

        Ok(Token { id, user_id })
    })
}

fn with_db(pool: Pool) -> impl Filter<Extract = (Client,), Error = Rejection> + Clone {
    warp::any().and_then(move || {
        let pool = pool.clone();
        async move {
            match pool.get().await {
                Ok(db) => Ok(db),
                Err(_) => Err(warp::reject::custom(ServiceUnavailableRejection)),
            }
        }
    })
}

#[derive(Debug)]
struct ServiceUnavailableRejection;
impl warp::reject::Reject for ServiceUnavailableRejection {}

#[derive(Debug)]
struct TokenFormatRejection;
impl warp::reject::Reject for TokenFormatRejection {}

#[derive(Debug)]
struct UnauthorizedRejection;
impl warp::reject::Reject for UnauthorizedRejection {}

async fn handle_rejection(err: Rejection) -> Result<impl warp::Reply, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "resource not found";
    } else if let Some(TokenFormatRejection) = err.find() {
        code = StatusCode::BAD_REQUEST;
        message = "invalid token secret format";
    } else if let Some(UnauthorizedRejection) = err.find() {
        code = StatusCode::UNAUTHORIZED;
        message = "invalid or expired token id";
    } else if let Some(_) = err.find::<warp::reject::MethodNotAllowed>() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "method not allowed";
    } else {
        eprintln!("unhandled rejection: {:?}", err);
        code = StatusCode::SERVICE_UNAVAILABLE;
        message = "service unavailable";
    }

    let json = warp::reply::json(&JsonError { error: message });

    Ok(warp::reply::with_status(json, code))
}

#[tokio::main]
async fn main() {
    let pool = deadpool_postgres::Config {
        user: Some("auth".into()),
        password: Some("auth".into()),
        dbname: Some("auth".into()),
        host: Some("localhost".into()),
        port: Some(5432),

        application_name: None, channel_binding: None, connect_timeout: None, hosts: None,
        keepalives: None, keepalives_idle: None, manager: None, options: None, pool: None,
        ports: None, ssl_mode: None, target_session_attrs: None,
    }.create_pool(tokio_postgres::NoTls).unwrap();

    let post_tokens = warp::path::end()
        .and(warp::post())
        .and(warp::body::content_length_limit(1024))
        .and(warp::body::json())
        .and(with_db(pool.clone()))
        .and_then(post_tokens);

    let get_tokens = warp::path::end()
        .and(warp::get())
        .and(with_token(pool.clone()))
        .and(with_db(pool.clone()))
        .and_then(get_tokens);

    let get_tokens_id = path_token_id()
        .and(warp::get())
        .and(with_token(pool.clone()))
        .and(with_db(pool.clone()))
        .and_then(get_tokens_id);

    let delete_tokens_id = path_token_id()
        .and(warp::delete())
        .and(with_token(pool.clone()))
        .and(with_db(pool))
        .and_then(delete_tokens_id);

    let routes = warp::path("tokens").and(
        post_tokens
            .or(get_tokens)
            .or(get_tokens_id)
            .or(delete_tokens_id)
            .recover(handle_rejection)
    );

    warp::serve(routes)
        .run(([127, 0, 0, 1], 3030))
        .await;
}
