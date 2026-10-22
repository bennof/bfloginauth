# bfloginauth

A small login server in Rust that works like an OAuth 2 service:

- Login page (embedded, no JavaScript)
- **Authorization code flow with PKCE (S256)**
- **Access tokens as JWTs**, signed with Ed25519 (`alg: EdDSA`), public key via JWKS
- **Refresh tokens** with rotation and theft detection (in memory)
- `/verify` endpoint for nginx `auth_request`
- Users, roles, claims and allowed redirects in **one TOML file**, reloaded without restart
- CLI to manage users and redirects

## Install from a release

Static Linux binaries (x86_64, aarch64) are attached to each [release](https://github.com/bennof/bfloginauth/releases).
No Rust needed on the server:

```sh
curl -L https://github.com/bennof/bfloginauth/releases/latest/download/bfloginauth-$(uname -m)-linux.tar.gz | tar xz
cd bfloginauth && sudo make install
```

New releases are built by GitHub Actions when a tag is pushed: `git tag v0.1.0 && git push origin v0.1.0`.

## Quick start

```sh
cargo build --release
B=./target/release/bfloginauth

$B init                                   # creates bfloginauth.toml
$B user add benno --role admin            # prompts for the password
$B redirect add https://app.example.com/callback
$B                                        # same as: $B serve
```

Config path: `-c path.toml` or `BFLOGINAUTH_CONFIG`; otherwise `./bfloginauth.toml` if it exists, else
`/etc/bfloginauth/bfloginauth.toml` (`init` without a path always writes to the current directory).
Log level: `RUST_LOG=debug`.
On first start, `ed25519.pem` is created next to the config (mode 0600).

A systemd unit is in [deploy/bfloginauth.service](deploy/bfloginauth.service).
On a Linux server, `make && sudo make install` installs the binary to `/usr/local/bin`, creates the
`bfloginauth` user, `/etc/bfloginauth/bfloginauth.toml` and the systemd unit, and copies the nginx snippets
to `/etc/nginx/snippets/`. Existing config and snippets are kept. Then: `sudo systemctl enable --now bfloginauth`.

## CLI

| Command | Purpose |
|---|---|
| `user add <name> [-r role]…` | Add a user |
| `user rm <name>` | Remove a user |
| `user ls` | List users |
| `user passwd <name>` | Change a password |
| `user roles <name> [--set a,b] [--add x] [--remove y]` | Show or change roles |
| `user disable/enable <name>` | Disable or re-enable a user |
| `redirect add/rm/ls [url]` | Manage allowed redirect URLs |
| `hash-password` | Print a hash only |

Passwords are prompted without echo, or read from stdin with `--password-stdin` (or when there is no terminal).
The CLI edits the file without losing comments and rejects changes that would make the config invalid.
A running server picks up changes within about 2 s (or immediately on `kill -HUP`).

## Flow for an app

1. The app creates a `code_verifier` (43–128 characters) and `code_challenge = BASE64URL(SHA256(verifier))`.
2. It redirects the browser to
   `https://example.com/login/authorize?response_type=code&client_id=app1&redirect_uri=…&state=…&code_challenge=…&code_challenge_method=S256`
3. After login, the browser lands on `redirect_uri?code=…&state=…` (the app checks `state`).
4. The app exchanges the code:
   ```
   POST /login/token  (application/x-www-form-urlencoded)
   grant_type=authorization_code&code=…&redirect_uri=…&client_id=app1&code_verifier=…
   ```
   → `{"access_token","token_type":"Bearer","expires_in","refresh_token"}`
5. Refresh: `grant_type=refresh_token&refresh_token=…`. Each refresh returns a **new** refresh token.
   If an old token is used again, the server revokes the whole session.
6. Logout: `POST /login/token` with `grant_type=revoke&refresh_token=…`. This revokes the whole session.

`redirect_uri` must match an entry in `allowed_redirects` **exactly**.
`client_id` can be any string and becomes the `aud` claim. Without `client_id`, `server.audience` is used.

### CORS

Browser apps on other origins (e.g. `https://apps.example.com`) that call `/token` or `/.well-known/…`
directly need their origin listed in the config:

```toml
allowed_origins = ["https://example.com", "https://apps.example.com"]
```

An origin is `scheme://host[:port]`, without path or trailing slash. Other origins get no CORS headers,
so the browser blocks the response. Changes apply without restart. `/authorize` is a normal page
navigation and needs no CORS.

### Access token

```json
{ "iss": "https://example.com/login", "sub": "benno", "aud": "app1",
  "iat": …, "nbf": …, "exp": …, "jti": "…", "roles": ["admin"], …claims }
```

Backends can verify the token themselves with the key from `/login/.well-known/jwks.json` (OKP/Ed25519).
Server metadata is available at `/login/.well-known/oauth-authorization-server`.

## Browser client

[deploy/js/bfloginauth.js](deploy/js/bfloginauth.js) is a small ES module that handles PKCE, the code
exchange, token refresh and logout. The server also serves it at `/login/bfloginauth.js`; loaded from
there it uses that URL as the issuer. Each release also has `bfloginauth.js` as a separate download
for apps that host it themselves (no CORS needed to load it); a copied file needs the `issuer` option.

```js
import { BfLogin } from "https://example.com/login/bfloginauth.js";

const auth = new BfLogin({
  redirectUri: "https://apps.example.com/callback",  // must be in allowed_redirects
  storage: "session",                                 // "session" (default), "local" or "memory"
  // issuer: "https://example.com/login",            // only for a copied file
  // clientId: "app1",                                // optional, becomes `aud`
});

const cb = await auth.handleCallback();   // on the callback page: exchanges ?code=…
if (cb) location.replace(cb.returnTo);

if (!auth.isLoggedIn()) await auth.login();          // redirects to the login page

auth.user();                               // { name, roles, claims }
auth.hasRole("admin");
const res = await auth.fetch("/api/data");  // adds the Bearer token, retries once after 401
await auth.logout({ redirectTo: "/" });
auth.onChange((user) => render(user));
```

The access token is refreshed automatically shortly before it expires. With `storage: "local"` the
session is shared between tabs and survives a browser restart; refreshes are coordinated between tabs.
Pages on another origin need that origin in `allowed_origins` (also for loading the script).
`crypto.subtle` requires HTTPS (or `localhost`).

## nginx

`make install` copies these files (existing files are kept):

| File | Goes to | Purpose |
|---|---|---|
| [bfloginauthzone.conf](deploy/nginx/conf.d/bfloginauthzone.conf) | `/etc/nginx/conf.d/` (`http {}` level) | Rate limit zone used by the login snippet |
| [bfloginauth-login-server.conf](deploy/nginx/snippets/bfloginauth-login-server.conf) | `include` in `server {}` of the login domain | Expose the login server under `/login/` |
| [bfloginauth-verify-endpoint.conf](deploy/nginx/snippets/bfloginauth-verify-endpoint.conf) | `include` in every `server {}` with protected locations | Internal token check `/login/_auth-verify` |
| [bfloginauth-verify.conf](deploy/nginx/snippets/bfloginauth-verify.conf) | `include` in `location {}` | Require a valid token and one of the roles in `$bfloginauth_roles` |

The snippets expect bfloginauth on `127.0.0.1:8080`; adjust them if `[server].listen` differs.

```nginx
server {
    server_name example.com;
    include snippets/bfloginauth-login-server.conf;
    include snippets/bfloginauth-verify-endpoint.conf;

    location /teacher/ {
        set $bfloginauth_roles "teacher,admin";   # "" = any valid token
        auth_request /login/_auth-verify;
        proxy_pass http://127.0.0.1:3000/;
    }
}

server {
    server_name apps.example.com;
    include snippets/bfloginauth-verify-endpoint.conf;

    location / {
        include snippets/bfloginauth-verify.conf;
        proxy_pass http://127.0.0.1:9000/;
    }
}
```

Set the roles in the location, never at `server {}` level: that would also run during the
internal check and clear the roles.

`/verify` reads only `Authorization: Bearer …` and answers `200` (headers `X-Auth-User`, `X-Auth-Roles`),
`401`, or `403` (role missing). Removed or disabled users get `401` immediately, even if their token has not expired.

## Endpoints

nginx exposes the server under `/login/` and strips the prefix
(see [bfloginauth-login-server.conf](deploy/nginx/snippets/bfloginauth-login-server.conf)).
Set `issuer` to the public URL including the prefix, e.g. `https://example.com/login`.

| Method | Public path | Purpose |
|---|---|---|
| GET/POST | `/login/authorize` | Login page / login |
| POST | `/login/token` | `grant_type=authorization_code`: exchange a code<br>`grant_type=refresh_token`: get new tokens<br>`grant_type=revoke`: log out |
| GET | `/login/.well-known/jwks.json` | Public key |
| GET | `/login/.well-known/oauth-authorization-server` | Metadata |
| GET | `/login/bfloginauth.js` | Browser client (ES module) |

Internal only (not reachable from outside): `/verify`, called by nginx `auth_request`.

## Limitations

- Refresh tokens and codes are kept in memory. After a restart, everyone has to log in again.
- The login server keeps no session (no SSO): every `/authorize` request shows the login form.
- Changes to `listen` and `key_file` take effect only after a restart.
- Single instance only (no shared state between processes).

## License

MIT, © 2026 Benjamin Benno Falkner. See [LICENSE](LICENSE).
