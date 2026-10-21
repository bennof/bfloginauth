// Copyright (c) 2026 Benjamin Benno Falkner
// SPDX-License-Identifier: MIT

//! In-memory state: authorization codes, refresh tokens (with rotation and
//! reuse detection) and failed login attempts.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::keys::{random_token, sha256};

pub struct AuthCode {
    pub user: String,
    pub client_id: Option<String>,
    pub redirect_uri: String,
    pub code_challenge: Option<String>,
    pub expires: Instant,
}

#[derive(Clone)]
pub struct RefreshEntry {
    pub user: String,
    pub client_id: Option<String>,
    /// All tokens of one login session share a family.
    pub family: String,
    pub expires: Instant,
}

struct Failures {
    count: u32,
    first: Instant,
    locked_until: Option<Instant>,
}

#[derive(Default)]
pub struct Store {
    codes: HashMap<String, AuthCode>,
    /// Keyed by the token's SHA-256; the token itself is never stored.
    refresh: HashMap<[u8; 32], RefreshEntry>,
    /// Already rotated tokens → family, to detect reuse (theft).
    used: HashMap<[u8; 32], (String, Instant)>,
    failures: HashMap<String, Failures>,
}

pub enum RefreshError {
    Invalid,
    /// An already used token was presented again; the family has been revoked.
    Reused,
}

impl Store {
    pub fn insert_code(&mut self, code: AuthCode) -> String {
        let token = random_token();
        self.codes.insert(token.clone(), code);
        token
    }

    /// Codes are single use: taking one always removes it.
    pub fn take_code(&mut self, code: &str) -> Option<AuthCode> {
        self.codes
            .remove(code)
            .filter(|c| c.expires > Instant::now())
    }

    pub fn issue_refresh(&mut self, entry: RefreshEntry) -> String {
        let token = random_token();
        self.refresh.insert(sha256(token.as_bytes()), entry);
        token
    }

    /// Remove the token and return its entry (the caller issues a new one).
    pub fn rotate(&mut self, token: &str) -> Result<RefreshEntry, RefreshError> {
        let h = sha256(token.as_bytes());
        if let Some((family, _)) = self.used.get(&h).cloned() {
            self.revoke_family(&family);
            return Err(RefreshError::Reused);
        }
        let entry = self.refresh.remove(&h).ok_or(RefreshError::Invalid)?;
        if entry.expires <= Instant::now() {
            return Err(RefreshError::Invalid);
        }
        self.used.insert(h, (entry.family.clone(), entry.expires));
        Ok(entry)
    }

    /// Revoke the whole session the token belongs to. Returns the user.
    pub fn revoke(&mut self, token: &str) -> Option<String> {
        let h = sha256(token.as_bytes());
        let (family, user) = match self.refresh.get(&h) {
            Some(e) => (e.family.clone(), Some(e.user.clone())),
            None => (self.used.get(&h)?.0.clone(), None),
        };
        self.revoke_family(&family);
        user
    }

    fn revoke_family(&mut self, family: &str) {
        self.refresh.retain(|_, e| e.family != family);
    }

    pub fn is_locked(&self, user: &str) -> bool {
        self.failures
            .get(user)
            .and_then(|f| f.locked_until)
            .is_some_and(|t| t > Instant::now())
    }

    pub fn record_failure(&mut self, user: &str, max: u32, lockout: Duration) {
        let now = Instant::now();
        let f = self.failures.entry(user.to_string()).or_insert(Failures {
            count: 0,
            first: now,
            locked_until: None,
        });
        if now.duration_since(f.first) > lockout {
            f.count = 0;
            f.first = now;
        }
        f.count += 1;
        if max > 0 && f.count >= max {
            f.locked_until = Some(now + lockout);
            f.count = 0;
            f.first = now;
        }
    }

    pub fn clear_failures(&mut self, user: &str) {
        self.failures.remove(user);
    }

    pub fn cleanup(&mut self, lockout: Duration) {
        let now = Instant::now();
        self.codes.retain(|_, c| c.expires > now);
        self.refresh.retain(|_, e| e.expires > now);
        self.used.retain(|_, (_, exp)| *exp > now);
        self.failures.retain(|_, f| {
            f.locked_until.is_some_and(|t| t > now) || now.duration_since(f.first) <= lockout
        });
    }
}
