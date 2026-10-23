# bfloginauth

A small login server in Rust that works like an OAuth 2 service, made to run behind nginx:

- Login page (embedded, no JavaScript)
- **Authorization code flow with PKCE (S256)**
- **Access tokens as JWTs**, signed with Ed25519 (`alg: EdDSA`), public key via JWKS
- **Refresh tokens** with rotation and theft detection (in memory)
- Token check for nginx `auth_request`, optionally with roles
- CORS for browser apps on other origins
- Browser client (`bfloginauth.js`) that handles PKCE, tokens, refresh and logout
- Users, roles, claims, redirects and origins in **one TOML file**, reloaded without restart
- CLI to manage users and redirects

## Server setup

### 1. Install

Static Linux binaries (x86_64, aarch64) are attached to each
[release](https://github.com/bennof/bfloginauth/releases). No Rust needed on the server:

```sh
curl -L https://github.com/bennof/bfloginauth/releases/latest/download/bfloginauth-$(uname -m)-linux.tar.gz | tar xz
cd bfloginauth && sudo make install
```

`latest` only points to stable releases. For a pre-release (`-alpha`, `-beta`, `-rc`) use its tag:
`…/releases/download/v0.1.0-alpha.3/bfloginauth-$(uname -m)-linux.tar.gz`.

`make install`:

| What | Target | On update |
|---|---|---|
| Binary | `/usr/local/bin/bfloginauth` | replaced |
| systemd unit | `/etc/systemd/system/bfloginauth.service` | replaced (use `systemctl edit` for changes) |
| User `bfloginauth` | — | created if missing |
| Config | `/etc/bfloginauth/bfloginauth.toml` | created if missing, otherwise kept |
| nginx snippets | `/etc/nginx/snippets/`, `/etc/nginx/conf.d/` | copied if missing, otherwise kept |

The signing key `/etc/bfloginauth/ed25519.pem` is created on the first start (mode 0600).
After an update: `sudo systemctl restart bfloginauth`.

### 2. Configure

```sh
sudo -u bfloginauth nano /etc/bfloginauth/bfloginauth.toml
```

```toml
# Lists must stay above the first [section].
allowed_redirects = [
  "https://apps.example.com/callback",
]
allowed_origins = [
  "https://example.com",
  "https://apps.example.com",
]

[server]
listen = "127.0.0.1:8080"
issuer = "https://example.com/login"
```

- **`issuer`**: the public URL of the login server **including** the `/login` prefix, without trailing
  slash. It becomes the `iss` claim and the base of all endpoint URLs. Changing it invalidates all tokens.
- **`allowed_redirects`**: URLs the login may return to. They must match the app's `redirect_uri`
  **exactly** (no wildcards; `…/callback` and `…/callback/` differ).
- **`allowed_origins`**: browser origins (`https://host[:port]`, no path, no trailing slash) that may
  call `/token`, `/.well-known/…` and load `bfloginauth.js` from another origin (CORS).
- **`listen`**: if you change the port, change it in the nginx snippets too.

The full template with all options is [deploy/bfloginauth.toml](deploy/bfloginauth.toml).

Changes are picked up within about 2 s (or `sudo systemctl reload bfloginauth`), except `listen` and
`key_file`. An invalid file is rejected and the previous config stays active. Check with
`journalctl -u bfloginauth -n 5`: `Config reloaded` or `Config not applied …` with the reason.

### 3. Add users and redirects

```sh
sudo -u bfloginauth bfloginauth user add benno -r admin
sudo -u bfloginauth bfloginauth redirect add https://apps.example.com/callback
```

### 4. nginx

In the HTTPS `server {}` block of the login domain:

```nginx
include snippets/bfloginauth-login-server.conf;
```

Then:

```sh
sudo nginx -t && sudo systemctl reload nginx
sudo systemctl enable --now bfloginauth
curl -s https://example.com/login/.well-known/oauth-authorization-server
```

The last command should return JSON with your `issuer`. See [nginx](#nginx) for protecting APIs.

## CLI

Run it as the service user so files keep the right owner: `sudo -u bfloginauth bfloginauth …`.

| Command | Purpose |
|---|---|
| `user add <name> [-r role,…]` | Add a user (prompts for the password) |
| `user rm <name>` | Remove a user |
| `user ls` | List users |
| `user passwd <name>` | Change a password |
| `user roles <name> [--set a,b] [--add x] [--remove y]` | Show or change roles |
| `user disable/enable <name>` | Block or unblock a user |
| `redirect add/rm/ls [url]` | Manage allowed redirect URLs |
| `hash-password` | Print an Argon2id hash |
| `init` | Write the config template to the current directory |
| `serve` | Run the server (default) |

- Config path: `-c path.toml` or `BFLOGINAUTH_CONFIG`; otherwise `./bfloginauth.toml` if it exists,
  else `/etc/bfloginauth/bfloginauth.toml`.
- Passwords are prompted without echo (pasting works) or read with `--password-stdin`; at least 8 characters.
- The CLI keeps comments in the file and refuses changes that would make the config invalid.
- `allowed_origins` has no CLI command; edit the file.
- Log level: `RUST_LOG=debug`.

## Browser client

[deploy/js/bfloginauth.js](deploy/js/bfloginauth.js) is a small ES module. It is served at
`/login/bfloginauth.js` and attached to each release as a separate file.

```js
import { BfLogin } from "https://example.com/login/bfloginauth.js";

const auth = new BfLogin({
  redirectUri: "https://apps.example.com/callback",  // must be in allowed_redirects
  storage: "session",                                 // "session" (default), "local" or "memory"
  // issuer: "https://example.com/login",            // required for a self-hosted copy
  // clientId: "app1",                                // optional, becomes `aud`
});

const cb = await auth.handleCallback();   // on the callback page: exchanges ?code=…
if (cb) location.replace(cb.returnTo);

if (!auth.isLoggedIn()) await auth.login();          // redirects to the login page

auth.user();                                // { name, roles, claims }
auth.hasRole("admin");
const res = await auth.fetch("/api/data");  // adds the Bearer token, retries once after 401
await auth.logout({ redirectTo: "/" });
auth.onChange((user) => render(user));
```

- Loaded from the server, the script uses its own URL as issuer. A self-hosted copy needs `issuer`;
  it needs no CORS to load, but the app's origin must still be in `allowed_origins` for `/token`.
- The access token is refreshed shortly before it expires. With `storage: "local"` the session is
  shared between tabs and survives a browser restart; tabs coordinate refreshes.
- The script sets no cookies and only talks to the login server.
- `crypto.subtle` requires HTTPS (or `localhost`).

## nginx

| File | Goes to | Purpose |
|---|---|---|
| [bfloginauthzone.conf](deploy/nginx/conf.d/bfloginauthzone.conf) | `/etc/nginx/conf.d/` (`http {}` level) | Rate limit zone for the login form |
| [bfloginauth-login-server.conf](deploy/nginx/snippets/bfloginauth-login-server.conf) | `include` in `server {}` of the login domain | Expose the login server under `/login/` |
| [bfloginauth-verify-endpoint.conf](deploy/nginx/snippets/bfloginauth-verify-endpoint.conf) | `include` in every `server {}` with protected locations | Internal token check `/login/_auth-verify` |
| [bfloginauth-verify.conf](deploy/nginx/snippets/bfloginauth-verify.conf) | `include` in `location {}` | Token check with the roles `user,admin` |

The snippets expect bfloginauth on `127.0.0.1:8080`; adjust them if `[server].listen` differs.

### Protecting an API

```nginx
server {
    server_name apps.example.com;
    include snippets/bfloginauth-verify-endpoint.conf;

    location /api/ {
        set $bfloginauth_roles "teacher,admin";   # any one of them; "" = any valid token
        auth_request /login/_auth-verify;
        proxy_pass http://127.0.0.1:9000/;
    }
}
```

- Result: `401` without a valid token, `403` without one of the roles, otherwise the request goes on.
- Roles are **or**: `"teacher,admin"` lets in users with either role.
- Set the roles in the location, never at `server {}` level: that would also run during the internal
  check and clear the roles.
- Never put `auth_request` at `server {}` level of the login domain: it would also block `/login/…`.
- Protect APIs, not pages: a browser sends no Bearer token when opening a page. The page loads the
  script, which calls the API with `auth.fetch()`.
- CORS preflight requests (`OPTIONS`) skip the token check and go to the backend, which must answer
  them with its own CORS headers.
- Removed or disabled users get `401` immediately, even if their token has not expired.
- The backend can read the user from the `X-Auth-User` and `X-Auth-Roles` response headers of the check
  (`auth_request_set $user $upstream_http_x_auth_user;`).

## Protocol

For apps that do not use the browser client.

| Method | Public path | Purpose |
|---|---|---|
| GET/POST | `/login/authorize` | Login page / login |
| POST | `/login/token` | `grant_type=authorization_code`: exchange a code<br>`grant_type=refresh_token`: get new tokens<br>`grant_type=revoke`: log out |
| GET | `/login/.well-known/jwks.json` | Public key |
| GET | `/login/.well-known/oauth-authorization-server` | Metadata |
| GET | `/login/bfloginauth.js` | Browser client |

`/login/` itself returns 404. `/verify` is internal only (called by nginx `auth_request`).

1. Create a `code_verifier` (43–128 characters) and `code_challenge = BASE64URL(SHA256(verifier))`.
2. Redirect the browser to
   `/login/authorize?response_type=code&redirect_uri=…&state=…&code_challenge=…&code_challenge_method=S256`
   (optional `client_id`).
3. After login the browser lands on `redirect_uri?code=…&state=…`. Check `state`; the code is valid
   for 60 s and only once.
4. Exchange it: `POST /login/token` (form-encoded)
   `grant_type=authorization_code&code=…&redirect_uri=…&code_verifier=…`
   → `{"access_token","token_type":"Bearer","expires_in","refresh_token"}`
5. Refresh: `grant_type=refresh_token&refresh_token=…`. Each refresh returns a **new** refresh token;
   reusing an old one revokes the whole session.
6. Logout: `grant_type=revoke&refresh_token=…`.

`client_id` is optional. If sent, it must be the same for authorize and token, and it becomes `aud`
(otherwise `server.audience`, if set).

Access token claims:

```json
{ "iss": "https://example.com/login", "sub": "benno", "aud": "app1",
  "iat": …, "nbf": …, "exp": …, "jti": "…", "roles": ["admin"], …claims }
```

Backends can verify tokens themselves with the key from `/login/.well-known/jwks.json` (OKP/Ed25519).

## Login page

The login and error pages are templates in [deploy/html/](deploy/html/):

| File | Placeholders (in double braces) |
|---|---|
| [login.html](deploy/html/login.html) | `title`, `style`, `error`, `hidden`, `username`, `focus_user`, `focus_password` |
| [error.html](deploy/html/error.html) | `title`, `style`, `message` |
| [style.css](deploy/html/style.css) | inlined into `style` of both pages (light and dark mode) |

- The templates are embedded at build time, like `deploy/js/bfloginauth.js`: changes need a new build.
- Only the heading can be changed without a build, with `title` in the config.
- Values from the request are HTML-escaped before they are inserted.
- The page sends a strict Content Security Policy (`default-src 'none'; style-src 'unsafe-inline'`):
  no scripts, no external files. A logo has to be inline SVG in `login.html`; image files or
  `data:` URLs are blocked.
- Keep the form fields `username` and `password`, the `{{hidden}}` placeholder and `method="post"`
  without `action`.

## Development

```sh
make          # cargo fmt + cargo build --release
make lint     # cargo clippy -- -D warnings
```

Releases are built by GitHub Actions when a `v*` tag is pushed. Set the same version in
`Cargo.toml` first and run `cargo build` so `Cargo.lock` follows:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

Tags with a hyphen (`v0.1.0-alpha.3`) become pre-releases. `gh workflow run release` builds without
publishing.

## Limitations

- Refresh tokens and codes are kept in memory. After a restart, everyone has to log in again.
- The login server keeps no session (no SSO): every login shows the login form.
- Single instance only (no shared state between processes).

## License

MIT, © 2026 Benjamin Benno Falkner. See [LICENSE](LICENSE).
