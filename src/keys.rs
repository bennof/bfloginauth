// Copyright (c) 2026 Benjamin Benno Falkner
// SPDX-License-Identifier: MIT

//! Ed25519 key, JWT signing (alg = EdDSA) and JWKS.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub struct Keys {
    signing: SigningKey,
    verifying: VerifyingKey,
    pub kid: String,
}

impl Keys {
    /// Load the key, or create a new one (file mode 0600).
    pub fn load_or_create(path: &Path) -> Result<Self> {
        let signing = if path.exists() {
            let pem = std::fs::read_to_string(path).with_context(|| {
                format!("Cannot read key {}", path.display())
            })?;
            SigningKey::from_pkcs8_pem(&pem)
                .map_err(|e| anyhow::anyhow!("Invalid key {}: {e}", path.display()))?
        } else {
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            let key = SigningKey::from_bytes(&seed);
            let pem = key
                .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
                .map_err(|e| anyhow::anyhow!("PEM-Export fehlgeschlagen: {e}"))?;
            write_private(path, pem.as_bytes())?;
            tracing::info!("Created new Ed25519 key: {}", path.display());
            key
        };
        let verifying = signing.verifying_key();
        let kid = B64.encode(&Sha256::digest(verifying.as_bytes())[..12]);
        Ok(Self {
            signing,
            verifying,
            kid,
        })
    }

    pub fn sign(&self, claims: &Value) -> String {
        let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": self.kid });
        let input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).expect("json")),
            B64.encode(serde_json::to_vec(claims).expect("json"))
        );
        let sig = self.signing.sign(input.as_bytes());
        format!("{input}.{}", B64.encode(sig.to_bytes()))
    }

    /// Checks format and signature only; the caller checks time claims and issuer.
    pub fn verify(&self, token: &str) -> Option<Map<String, Value>> {
        let mut parts = token.split('.');
        let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let header: Value = serde_json::from_slice(&B64.decode(h).ok()?).ok()?;
        if header.get("alg")?.as_str()? != "EdDSA" {
            return None;
        }
        let sig = Signature::from_slice(&B64.decode(s).ok()?).ok()?;
        let input = &token[..h.len() + 1 + p.len()];
        self.verifying.verify_strict(input.as_bytes(), &sig).ok()?;
        match serde_json::from_slice(&B64.decode(p).ok()?).ok()? {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }

    pub fn jwks(&self) -> Value {
        json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "kid": self.kid,
                "x": B64.encode(self.verifying.as_bytes()),
            }]
        })
    }
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("Cannot write key {}", path.display()))?;
    f.write_all(data)?;
    Ok(())
}

/// Random URL-safe token (256 bits).
pub fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    B64.encode(b)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn pkce_s256(verifier: &str) -> String {
    B64.encode(sha256(verifier.as_bytes()))
}
