// Copyright (c) 2026 Benjamin Benno Falkner
// SPDX-License-Identifier: MIT

//! Configuration: one TOML file with server settings, allowed redirect URLs
//! and users.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use argon2::PasswordHash;
use serde::Deserialize;

/// Claim names set by the server itself; per-user claims must not override them.
pub const RESERVED_CLAIMS: &[&str] = &["iss", "sub", "aud", "exp", "iat", "nbf", "jti", "roles"];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub allowed_redirects: Vec<String>,
    #[serde(default)]
    pub users: BTreeMap<String, User>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Public base URL of the server (as exposed by nginx).
    pub issuer: String,
    /// `aud` claim used when the client sends no `client_id`.
    #[serde(default)]
    pub audience: Option<String>,
    /// Ed25519 key (PKCS#8 PEM), relative to the config file. Created if missing.
    #[serde(default = "default_key_file")]
    pub key_file: PathBuf,
    #[serde(default = "default_access_ttl", with = "humantime_serde")]
    pub access_ttl: Duration,
    #[serde(default = "default_refresh_ttl", with = "humantime_serde")]
    pub refresh_ttl: Duration,
    #[serde(default = "default_code_ttl", with = "humantime_serde")]
    pub code_ttl: Duration,
    /// Require PKCE (S256) for every login.
    #[serde(default = "default_true")]
    pub require_pkce: bool,
    /// Failed attempts per username before the login is locked.
    #[serde(default = "default_max_failed")]
    pub max_failed_logins: u32,
    #[serde(default = "default_lockout", with = "humantime_serde")]
    pub lockout: Duration,
    /// Heading of the login page.
    #[serde(default = "default_title")]
    pub title: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub password_hash: String,
    #[serde(default)]
    pub roles: Vec<String>,
    /// Extra claims copied into the access token.
    #[serde(default)]
    pub claims: BTreeMap<String, toml::Value>,
    #[serde(default)]
    pub disabled: bool,
}

fn default_listen() -> String {
    "127.0.0.1:8080".into()
}
fn default_key_file() -> PathBuf {
    "ed25519.pem".into()
}
fn default_access_ttl() -> Duration {
    Duration::from_secs(15 * 60)
}
fn default_refresh_ttl() -> Duration {
    Duration::from_secs(30 * 24 * 3600)
}
fn default_code_ttl() -> Duration {
    Duration::from_secs(60)
}
fn default_true() -> bool {
    true
}
fn default_max_failed() -> u32 {
    5
}
fn default_lockout() -> Duration {
    Duration::from_secs(5 * 60)
}
fn default_title() -> String {
    "Anmelden".into()
}

impl Config {
    /// Read and validate the file; `key_file` is resolved relative to the config file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Config {} kann nicht gelesen werden", path.display()))?;
        let mut cfg = Self::parse(&text)
            .with_context(|| format!("Config {} ist ungültig", path.display()))?;
        if cfg.server.key_file.is_relative() {
            let base = path.parent().unwrap_or(Path::new("."));
            cfg.server.key_file = base.join(&cfg.server.key_file);
        }
        Ok(cfg)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut cfg: Config = toml::from_str(text)?;
        cfg.server.issuer = cfg.server.issuer.trim_end_matches('/').to_string();
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        url::Url::parse(&self.server.issuer).context("server.issuer muss eine URL sein")?;
        for r in &self.allowed_redirects {
            check_redirect_url(r)?;
        }
        for (name, user) in &self.users {
            check_username(name)?;
            PasswordHash::new(&user.password_hash)
                .map_err(|e| anyhow::anyhow!("users.{name}.password_hash ist ungültig: {e}"))?;
            for key in user.claims.keys() {
                if RESERVED_CLAIMS.contains(&key.as_str()) {
                    bail!("users.{name}.claims.{key} ist reserviert");
                }
            }
        }
        Ok(())
    }

    pub fn base_url(&self) -> &str {
        &self.server.issuer
    }
}

pub fn check_username(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        bail!("Benutzername muss 1–64 Zeichen lang sein");
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
    {
        bail!(
            "Benutzername '{name}' enthält ungültige Zeichen (erlaubt: Buchstaben, Ziffern, . _ - @)"
        );
    }
    Ok(())
}

pub fn check_redirect_url(r: &str) -> Result<()> {
    let u = url::Url::parse(r).with_context(|| format!("Redirect '{r}' ist keine gültige URL"))?;
    if u.fragment().is_some() {
        bail!("Redirect '{r}' darf kein #Fragment enthalten");
    }
    if !matches!(u.scheme(), "https" | "http") {
        bail!("Redirect '{r}' muss http oder https sein");
    }
    Ok(())
}

/// Convert a TOML value to JSON (datetimes become strings).
pub fn toml_to_json(v: &toml::Value) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        toml::Value::String(s) => J::String(s.clone()),
        toml::Value::Integer(i) => J::from(*i),
        toml::Value::Float(f) => J::from(*f),
        toml::Value::Boolean(b) => J::Bool(*b),
        toml::Value::Datetime(d) => J::String(d.to_string()),
        toml::Value::Array(a) => J::Array(a.iter().map(toml_to_json).collect()),
        toml::Value::Table(t) => J::Object(
            t.iter()
                .map(|(k, v)| (k.clone(), toml_to_json(v)))
                .collect(),
        ),
    }
}
