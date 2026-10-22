// Copyright (c) 2026 Benjamin Benno Falkner
// SPDX-License-Identifier: MIT
//
// bfloginauth.js: browser client for bfloginauth (authorization code + PKCE).
//
//   import { BfLogin } from "https://example.com/login/bfloginauth.js";
//   const auth = new BfLogin({ redirectUri: location.origin + "/callback" });
//   await auth.handleCallback();          // on the redirect page
//   if (!auth.isLoggedIn()) auth.login();
//   const res = await auth.fetch("/api/data");

const TOKENS = "bfloginauth.tokens";
const PENDING = "bfloginauth.pending.";
const MARGIN_MS = 60_000; // refresh this long before the access token expires

// Issuer when served by bfloginauth itself: the directory of this script.
function defaultIssuer() {
  return new URL(".", import.meta.url).href;
}

function memoryStorage() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
  };
}

function pickStorage(s) {
  if (s && typeof s === "object") return s;
  if (s === "local") return localStorage;
  if (s === "memory") return memoryStorage();
  return sessionStorage;
}

function b64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function randomString(n) {
  return b64url(crypto.getRandomValues(new Uint8Array(n)));
}

async function s256(text) {
  return b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}

function decodeJwt(token) {
  const part = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
  const bytes = Uint8Array.from(atob(part), (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

export class BfLogin {
  /**
   * @param {object} [o]
   * @param {string} [o.issuer]       bfloginauth URL, e.g. "https://example.com/login"
   *                                  (default: where this script was loaded from)
   * @param {string} [o.redirectUri]  must be listed in allowed_redirects
   *                                  (default: current page without query)
   * @param {string} [o.clientId]     optional, becomes the token's `aud`
   * @param {"session"|"local"|"memory"|Storage} [o.storage]  where tokens are kept (default "session")
   * @param {boolean} [o.autoRefresh] refresh the access token before it expires (default true)
   */
  constructor({
    issuer = defaultIssuer(),
    redirectUri = location.origin + location.pathname,
    clientId,
    storage = "session",
    autoRefresh = true,
  } = {}) {
    this.issuer = issuer.replace(/\/+$/, "");
    this.redirectUri = redirectUri;
    this.clientId = clientId;
    this.autoRefresh = autoRefresh;
    this.store = pickStorage(storage);
    this._refreshing = null;
    this._timer = null;
    this._listeners = new Set();

    // Keep tabs in sync when tokens live in localStorage.
    if (this.store === globalThis.localStorage) {
      addEventListener("storage", (e) => {
        if (e.key === TOKENS) {
          this._schedule();
          this._emit();
        }
      });
    }
    this._schedule();
  }

  /** Redirect to the login page. After login the browser comes back to redirectUri. */
  async login({ returnTo = location.href } = {}) {
    const state = randomString(16);
    const verifier = randomString(48);
    // Always sessionStorage: it must survive the redirect, whatever `storage` is.
    sessionStorage.setItem(PENDING + state, JSON.stringify({ verifier, returnTo }));
    const p = new URLSearchParams({
      response_type: "code",
      redirect_uri: this.redirectUri,
      state,
      code_challenge: await s256(verifier),
      code_challenge_method: "S256",
    });
    if (this.clientId) p.set("client_id", this.clientId);
    location.assign(`${this.issuer}/authorize?${p}`);
  }

  /**
   * Call on the redirect page. Exchanges ?code=… for tokens and removes it from the URL.
   * Returns { returnTo } after a login, or null if the URL has no code.
   */
  async handleCallback() {
    const url = new URL(location.href);
    const q = url.searchParams;
    const code = q.get("code");
    const state = q.get("state");
    const error = q.get("error");
    if (!code && !error) return null;

    for (const k of ["code", "state", "error", "error_description"]) q.delete(k);
    history.replaceState(history.state, "", url.pathname + url.search + url.hash);

    const pending = state && sessionStorage.getItem(PENDING + state);
    if (state) sessionStorage.removeItem(PENDING + state);
    if (error) throw new Error(`bfloginauth: ${error}`);
    if (!pending) throw new Error("bfloginauth: unknown or expired login state");

    const { verifier, returnTo } = JSON.parse(pending);
    const data = await this._token({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.redirectUri,
      code_verifier: verifier,
    });
    this._save(data);
    return { returnTo };
  }

  /** True while a session (refresh token) exists. */
  isLoggedIn() {
    return this._load() !== null;
  }

  /** { name, roles, claims } from the access token, or null. */
  user() {
    const t = this._load();
    if (!t) return null;
    const claims = decodeJwt(t.access);
    return { name: claims.sub, roles: claims.roles || [], claims };
  }

  hasRole(...roles) {
    const u = this.user();
    return !!u && roles.some((r) => u.roles.includes(r));
  }

  /** A valid access token (refreshed if needed), or null when logged out. */
  async accessToken() {
    const t = this._load();
    if (!t) return null;
    if (t.expiresAt - Date.now() > MARGIN_MS) return t.access;
    return this.refresh();
  }

  /** fetch() with the Bearer token; on 401 refreshes once and retries. */
  async fetch(input, init = {}) {
    const send = (token) => {
      const headers = new Headers(init.headers);
      if (token) headers.set("Authorization", `Bearer ${token}`);
      return fetch(input, { ...init, headers });
    };
    const token = await this.accessToken();
    let res = await send(token);
    if (res.status === 401 && token) {
      const fresh = await this.refresh(token).catch(() => null);
      if (fresh) res = await send(fresh);
    }
    return res;
  }

  /**
   * Get a new access token now. `stale` is the token to replace (default: the
   * current one); if another tab already replaced it, that result is used.
   */
  refresh(stale) {
    if (!this._refreshing) {
      if (stale === undefined) stale = this._load()?.access;
      this._refreshing = this._refresh(stale).finally(() => (this._refreshing = null));
    }
    return this._refreshing;
  }

  /** End the session on the server and forget the tokens. */
  async logout({ redirectTo } = {}) {
    const t = this._load();
    this._clear();
    if (t) await this._token({ grant_type: "revoke", refresh_token: t.refresh }).catch(() => {});
    if (redirectTo) location.assign(redirectTo);
  }

  /** Called with user() whenever the login state changes. Returns an unsubscribe function. */
  onChange(cb) {
    this._listeners.add(cb);
    return () => this._listeners.delete(cb);
  }

  // ------------------------------------------------------------ internals

  async _refresh(stale) {
    const run = async () => {
      // Another tab may have refreshed meanwhile (shared localStorage).
      const t = this._load();
      if (!t) return null;
      if (t.access !== stale && t.expiresAt - Date.now() > MARGIN_MS) return t.access;
      try {
        const data = await this._token({ grant_type: "refresh_token", refresh_token: t.refresh });
        return this._save(data).access;
      } catch (e) {
        if (e.code === "invalid_grant") this._clear(); // session ended or revoked
        throw e;
      }
    };
    // One refresh at a time across tabs; refresh tokens are single use.
    return navigator.locks ? navigator.locks.request("bfloginauth.refresh", run) : run();
  }

  async _token(params) {
    if (this.clientId) params.client_id = this.clientId;
    const res = await fetch(`${this.issuer}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(params),
    });
    if (params.grant_type === "revoke") return null;
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const e = new Error(`bfloginauth: ${data.error || res.status} ${data.error_description || ""}`.trim());
      e.code = data.error;
      throw e;
    }
    return data;
  }

  _load() {
    try {
      return JSON.parse(this.store.getItem(TOKENS));
    } catch {
      return null;
    }
  }

  _save(data) {
    const t = {
      access: data.access_token,
      refresh: data.refresh_token,
      expiresAt: Date.now() + data.expires_in * 1000,
    };
    this.store.setItem(TOKENS, JSON.stringify(t));
    this._schedule();
    this._emit();
    return t;
  }

  _clear() {
    this.store.removeItem(TOKENS);
    this._schedule();
    this._emit();
  }

  _schedule() {
    clearTimeout(this._timer);
    const t = this.autoRefresh && this._load();
    if (!t) return;
    const ms = Math.max(0, t.expiresAt - Date.now() - MARGIN_MS);
    this._timer = setTimeout(() => this.refresh().catch(() => {}), ms);
  }

  _emit() {
    const u = this.user();
    for (const cb of this._listeners) cb(u);
  }
}
