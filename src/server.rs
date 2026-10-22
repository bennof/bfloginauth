// Copyright (c) 2026 Benjamin Benno Falkner
// SPDX-License-Identifier: MIT

//! HTTP endpoints:
//!
//! - `GET/POST /authorize`  login page, then redirect with `?code=…&state=…`
//! - `POST /token`          exchange a code or refresh token for tokens;
//!   `grant_type=revoke` logs out (revokes the session)
//! - `GET /.well-known/jwks.json`, `/.well-known/oauth-authorization-server`
//! - `GET /bfloginauth.js`  browser client (ES module)
//! - `* /verify`            internal, for nginx `auth_request` (Bearer header)

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{any, get, post};
use axum::{Form, Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::{Config, User, toml_to_json};
use crate::html;
use crate::keys::{Keys, pkce_s256, random_token};
use crate::store::{AuthCode, RefreshEntry, RefreshError, Store};

/// Allowed clock skew for exp/nbf.
const LEEWAY_SECS: u64 = 30;

pub struct AppState {
    config_path: PathBuf,
    config: RwLock<Arc<Config>>,
    keys: Keys,
    store: Mutex<Store>,
    /// Verified for unknown users so response timing does not reveal which users exist.
    dummy_hash: String,
}

type St = State<Arc<AppState>>;

impl AppState {
    fn cfg(&self) -> Arc<Config> {
        self.config.read().unwrap().clone()
    }

    fn reload(&self) -> Result<()> {
        let new = Config::load(&self.config_path)?;
        let old = self.cfg();
        if new.server.listen != old.server.listen || new.server.key_file != old.server.key_file {
            tracing::warn!("Changes to listen/key_file take effect only after a restart");
        }
        tracing::info!(
            users = new.users.len(),
            redirects = new.allowed_redirects.len(),
            "Config reloaded"
        );
        *self.config.write().unwrap() = Arc::new(new);
        Ok(())
    }
}

pub async fn run(config_path: PathBuf) -> Result<()> {
    let cfg = Config::load(&config_path)?;
    let keys = Keys::load_or_create(&cfg.server.key_file)?;
    let dummy_hash = Argon2::default()
        .hash_password(b"dummy", &SaltString::generate(&mut rand::rngs::OsRng))
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .to_string();
    let listen = cfg.server.listen.clone();
    tracing::info!(
        issuer = %cfg.server.issuer,
        kid = %keys.kid,
        users = cfg.users.len(),
        redirects = cfg.allowed_redirects.len(),
        "Starting bfloginauth"
    );

    let state = Arc::new(AppState {
        config_path,
        config: RwLock::new(Arc::new(cfg)),
        keys,
        store: Mutex::new(Store::default()),
        dummy_hash,
    });

    tokio::spawn(watch_config(state.clone()));
    #[cfg(unix)]
    tokio::spawn(reload_on_sighup(state.clone()));

    // Endpoints that browser apps on other origins call directly.
    let cors_routes = Router::new()
        .route("/token", post(token))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/bfloginauth.js", get(client_js))
        .layer(middleware::from_fn_with_state(state.clone(), cors));

    let app = Router::new()
        .route("/authorize", get(authorize_get).post(authorize_post))
        .route("/verify", any(verify))
        .merge(cors_routes)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("Cannot listen on {listen}"))?;
    tracing::info!("Listening on http://{listen}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Every 2 s, reload the config if the file changed, and purge expired entries.
async fn watch_config(state: Arc<AppState>) {
    let mtime = |p: &PathBuf| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    let mut last = mtime(&state.config_path);
    let mut last_cleanup = Instant::now();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
    loop {
        tick.tick().await;
        let now = mtime(&state.config_path);
        if now.is_some() && now != last {
            last = now;
            if let Err(e) = state.reload() {
                tracing::error!("Config not applied, keeping the previous one: {e:#}");
            }
        }
        if last_cleanup.elapsed().as_secs() >= 60 {
            last_cleanup = Instant::now();
            let lockout = state.cfg().server.lockout;
            state.store.lock().unwrap().cleanup(lockout);
        }
    }
}

#[cfg(unix)]
async fn reload_on_sighup(state: Arc<AppState>) {
    use tokio::signal::unix::{SignalKind, signal};
    let Ok(mut sig) = signal(SignalKind::hangup()) else {
        return;
    };
    while sig.recv().await.is_some() {
        if let Err(e) = state.reload() {
            tracing::error!("Config not applied, keeping the previous one: {e:#}");
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM-Handler");
        tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = ctrl_c.await;
    tracing::info!("Shutting down");
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------- CORS

/// Adds CORS headers for origins listed in `allowed_origins` and answers
/// preflight requests. No credentials: tokens travel in the request body or
/// the Authorization header, never in cookies.
async fn cors(State(st): St, req: Request, next: Next) -> Response {
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .filter(|o| st.cfg().allowed_origins.iter().any(|a| a == o))
        .and_then(|o| HeaderValue::from_str(o).ok());

    let preflight = req.method() == Method::OPTIONS;
    let mut res = if preflight {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(req).await
    };

    let h = res.headers_mut();
    h.append(header::VARY, HeaderValue::from_static("Origin"));
    if let Some(origin) = origin {
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        if preflight {
            h.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET, POST, OPTIONS"),
            );
            h.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("Content-Type, Authorization"),
            );
            h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
        }
    }
    res
}

// ---------------------------------------------------------------- /authorize

#[derive(Debug, Default, Deserialize)]
struct AuthorizeParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    scope: Option<String>,
}

impl AuthorizeParams {
    fn hidden(&self) -> Vec<(&'static str, &str)> {
        [
            ("response_type", &self.response_type),
            ("client_id", &self.client_id),
            ("redirect_uri", &self.redirect_uri),
            ("state", &self.state),
            ("code_challenge", &self.code_challenge),
            ("code_challenge_method", &self.code_challenge_method),
            ("scope", &self.scope),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.as_deref().map(|v| (k, v)))
        .collect()
    }
}

#[derive(Deserialize)]
struct LoginForm {
    #[serde(flatten)]
    params: AuthorizeParams,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

struct Validated {
    redirect_uri: String,
    client_id: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
}

enum AuthzError {
    /// Error without a trusted redirect_uri: show an error page.
    Page(String),
    /// Error with a valid redirect_uri: redirect back as OAuth specifies.
    Redirect(String),
}

fn page(status: StatusCode, html: String) -> Response {
    let mut res = (status, html).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    res
}

fn with_query(base: &str, pairs: &[(&str, Option<&str>)]) -> String {
    let mut u = url::Url::parse(base).expect("redirect_uri wurde validiert");
    {
        let mut q = u.query_pairs_mut();
        for (k, v) in pairs {
            if let Some(v) = v {
                q.append_pair(k, v);
            }
        }
    }
    u.to_string()
}

fn validate(cfg: &Config, p: &AuthorizeParams) -> Result<Validated, AuthzError> {
    let Some(redirect_uri) = p.redirect_uri.clone() else {
        return Err(AuthzError::Page("Parameter redirect_uri is missing.".into()));
    };
    if !cfg.allowed_redirects.contains(&redirect_uri) {
        return Err(AuthzError::Page(
            "This redirect_uri is not allowed.".into(),
        ));
    }
    let fail = |error: &str, desc: &str| {
        AuthzError::Redirect(with_query(
            &redirect_uri,
            &[
                ("error", Some(error)),
                ("error_description", Some(desc)),
                ("state", p.state.as_deref()),
            ],
        ))
    };
    if p.response_type.as_deref() != Some("code") {
        return Err(fail(
            "unsupported_response_type",
            "only response_type=code is supported",
        ));
    }
    match (&p.code_challenge, p.code_challenge_method.as_deref()) {
        (Some(c), Some("S256")) => {
            let ok = c.len() == 43
                && c.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            if !ok {
                return Err(fail("invalid_request", "malformed code_challenge"));
            }
        }
        (Some(_), _) => {
            return Err(fail(
                "invalid_request",
                "code_challenge_method must be S256",
            ));
        }
        (None, _) if cfg.server.require_pkce => {
            return Err(fail("invalid_request", "PKCE (S256) is required"));
        }
        (None, _) => {}
    }
    Ok(Validated {
        redirect_uri,
        client_id: p.client_id.clone(),
        state: p.state.clone(),
        code_challenge: p.code_challenge.clone(),
    })
}

fn authz_error(cfg: &Config, e: AuthzError) -> Response {
    match e {
        AuthzError::Page(msg) => page(
            StatusCode::BAD_REQUEST,
            html::error_page(&cfg.server.title, &msg),
        ),
        AuthzError::Redirect(url) => Redirect::to(&url).into_response(),
    }
}

async fn authorize_get(State(st): St, Query(p): Query<AuthorizeParams>) -> Response {
    let cfg = st.cfg();
    if let Err(e) = validate(&cfg, &p) {
        return authz_error(&cfg, e);
    }
    page(
        StatusCode::OK,
        html::login_page(&cfg.server.title, &p.hidden(), "", None),
    )
}

async fn authorize_post(State(st): St, Form(f): Form<LoginForm>) -> Response {
    let cfg = st.cfg();
    let v = match validate(&cfg, &f.params) {
        Ok(v) => v,
        Err(e) => return authz_error(&cfg, e),
    };
    let username = f.username.trim().to_string();
    let retry = |msg: &str| {
        page(
            StatusCode::UNAUTHORIZED,
            html::login_page(&cfg.server.title, &f.params.hidden(), &username, Some(msg)),
        )
    };

    if st.store.lock().unwrap().is_locked(&username) {
        tracing::warn!(user = %username, "Login locked (too many failed attempts)");
        return retry("Too many failed attempts. Please try again later.");
    }

    let user = cfg.users.get(&username).filter(|u| !u.disabled);
    let hash = user
        .map(|u| u.password_hash.clone())
        .unwrap_or_else(|| st.dummy_hash.clone());
    let password = f.password.clone();
    let ok = tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash)
            .map(|h| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &h)
                    .is_ok()
            })
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false);

    if !ok || user.is_none() {
        tracing::warn!(user = %username, "Login failed");
        st.store.lock().unwrap().record_failure(
            &username,
            cfg.server.max_failed_logins,
            cfg.server.lockout,
        );
        return retry("Wrong user name or password.");
    }

    let code = {
        let mut store = st.store.lock().unwrap();
        store.clear_failures(&username);
        store.insert_code(AuthCode {
            user: username.clone(),
            client_id: v.client_id,
            redirect_uri: v.redirect_uri.clone(),
            code_challenge: v.code_challenge,
            expires: Instant::now() + cfg.server.code_ttl,
        })
    };
    tracing::info!(user = %username, redirect = %v.redirect_uri, "Login successful");
    let target = with_query(
        &v.redirect_uri,
        &[("code", Some(&code)), ("state", v.state.as_deref())],
    );
    // 303: the browser follows with GET.
    Redirect::to(&target).into_response()
}

// ---------------------------------------------------------------- /token

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    client_id: Option<String>,
    refresh_token: Option<String>,
}

fn oauth_error(status: StatusCode, error: &str, desc: &str) -> Response {
    no_store(
        (
            status,
            Json(json!({ "error": error, "error_description": desc })),
        )
            .into_response(),
    )
}

fn no_store(mut res: Response) -> Response {
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res.headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    res
}

fn invalid_grant(desc: &str) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", desc)
}

async fn token(State(st): St, Form(req): Form<TokenRequest>) -> Response {
    let cfg = st.cfg();
    match req.grant_type.as_str() {
        "authorization_code" => {
            let Some(code) = req.code.as_deref() else {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "code missing");
            };
            let Some(c) = st.store.lock().unwrap().take_code(code) else {
                return invalid_grant("invalid or expired code");
            };
            if req.redirect_uri.as_deref() != Some(c.redirect_uri.as_str()) {
                return invalid_grant("redirect_uri mismatch");
            }
            if c.client_id.is_some() && req.client_id != c.client_id {
                return invalid_grant("client_id mismatch");
            }
            if let Some(challenge) = &c.code_challenge {
                let Some(verifier) = req.code_verifier.as_deref() else {
                    return invalid_grant("code_verifier missing");
                };
                if !(43..=128).contains(&verifier.len()) || pkce_s256(verifier) != *challenge {
                    return invalid_grant("code_verifier invalid");
                }
            }
            let Some(user) = cfg.users.get(&c.user).filter(|u| !u.disabled) else {
                return invalid_grant("user no longer exists");
            };
            issue_tokens(&st, &cfg, &c.user, user, c.client_id, random_token())
        }
        "refresh_token" => {
            let Some(rt) = req.refresh_token.as_deref() else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "refresh_token missing",
                );
            };
            let entry = match st.store.lock().unwrap().rotate(rt) {
                Ok(e) => e,
                Err(RefreshError::Invalid) => {
                    return invalid_grant("invalid or expired refresh_token");
                }
                Err(RefreshError::Reused) => {
                    tracing::warn!("Reused refresh token: session revoked");
                    return invalid_grant("refresh_token reused; session revoked");
                }
            };
            if req.client_id.is_some() && req.client_id != entry.client_id {
                return invalid_grant("client_id mismatch");
            }
            let Some(user) = cfg.users.get(&entry.user).filter(|u| !u.disabled) else {
                return invalid_grant("user no longer exists");
            };
            issue_tokens(&st, &cfg, &entry.user, user, entry.client_id, entry.family)
        }
        // Logout: revoke the whole session. Like RFC 7009, always answers 200,
        // even for unknown tokens.
        "revoke" => {
            if let Some(rt) = req.refresh_token.as_deref()
                && let Some(user) = st.store.lock().unwrap().revoke(rt)
            {
                tracing::info!(user = %user, "Session revoked (logout)");
            }
            no_store(StatusCode::OK.into_response())
        }
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "use authorization_code, refresh_token or revoke",
        ),
    }
}

fn issue_tokens(
    st: &AppState,
    cfg: &Config,
    username: &str,
    user: &User,
    client_id: Option<String>,
    family: String,
) -> Response {
    let now = now_secs();
    let ttl = cfg.server.access_ttl.as_secs();
    let mut claims = serde_json::Map::new();
    for (k, v) in &user.claims {
        claims.insert(k.clone(), toml_to_json(v));
    }
    claims.insert("iss".into(), json!(cfg.server.issuer));
    claims.insert("sub".into(), json!(username));
    if let Some(aud) = client_id.as_ref().or(cfg.server.audience.as_ref()) {
        claims.insert("aud".into(), json!(aud));
    }
    claims.insert("iat".into(), json!(now));
    claims.insert("nbf".into(), json!(now));
    claims.insert("exp".into(), json!(now + ttl));
    claims.insert("jti".into(), json!(random_token()));
    claims.insert("roles".into(), json!(user.roles));
    let access = st.keys.sign(&Value::Object(claims));

    let refresh = st.store.lock().unwrap().issue_refresh(RefreshEntry {
        user: username.to_string(),
        client_id,
        family,
        expires: Instant::now() + cfg.server.refresh_ttl,
    });

    no_store(
        Json(json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ttl,
            "refresh_token": refresh,
        }))
        .into_response(),
    )
}

// ---------------------------------------------------------------- /verify

#[derive(Deserialize)]
struct VerifyParams {
    /// Comma separated; the user needs at least one of these roles.
    /// Missing or empty: no role check.
    role: Option<String>,
    /// Optional expected `aud` value.
    aud: Option<String>,
}

fn unauthorized() -> Response {
    let mut res = StatusCode::UNAUTHORIZED.into_response();
    res.headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    res
}

async fn verify(State(st): St, Query(q): Query<VerifyParams>, headers: HeaderMap) -> Response {
    let cfg = st.cfg();
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| {
            h.strip_prefix("Bearer ")
                .or_else(|| h.strip_prefix("bearer "))
        })
        .map(str::trim)
    else {
        return unauthorized();
    };
    let Some(claims) = st.keys.verify(token) else {
        return unauthorized();
    };
    let now = now_secs();
    let num = |k: &str| claims.get(k).and_then(Value::as_u64);
    let valid = claims.get("iss").and_then(Value::as_str) == Some(cfg.server.issuer.as_str())
        && num("exp").is_some_and(|exp| exp + LEEWAY_SECS > now)
        && num("nbf").is_none_or(|nbf| nbf <= now + LEEWAY_SECS);
    if !valid {
        return unauthorized();
    }
    if let Some(aud) = &q.aud
        && claims.get("aud").and_then(Value::as_str) != Some(aud.as_str())
    {
        return unauthorized();
    }
    let Some(sub) = claims.get("sub").and_then(Value::as_str) else {
        return unauthorized();
    };
    // Removed or disabled users lose access immediately, not only when the token expires.
    let Some(user) = cfg.users.get(sub).filter(|u| !u.disabled) else {
        return unauthorized();
    };
    // No roles listed (missing or empty `role`): any valid token is enough.
    let required: Vec<&str> = q
        .role
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .collect();
    if !required.is_empty() && !required.iter().any(|r| user.roles.iter().any(|ur| ur == r)) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut res = StatusCode::OK.into_response();
    let h = res.headers_mut();
    if let Ok(v) = HeaderValue::from_str(sub) {
        h.insert("x-auth-user", v);
    }
    if let Ok(v) = HeaderValue::from_str(&user.roles.join(",")) {
        h.insert("x-auth-roles", v);
    }
    res
}

// ---------------------------------------------------------------- Discovery

/// Browser client; apps import it as an ES module (needs CORS for other origins).
const CLIENT_JS: &str = include_str!("../deploy/js/bfloginauth.js");

async fn client_js() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        CLIENT_JS,
    )
        .into_response()
}

async fn jwks(State(st): St) -> Response {
    let mut res = Json(st.keys.jwks()).into_response();
    res.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    res
}

async fn metadata(State(st): St) -> Json<Value> {
    let cfg = st.cfg();
    let base = cfg.base_url();
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }))
}
