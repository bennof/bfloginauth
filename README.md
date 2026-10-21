# bfloginauth

A small login server in Rust that works like an OAuth 2 service:

- Login page (embedded, no JavaScript)
- **Authorization code flow with PKCE (S256)**
- **Access tokens as JWTs**, signed with Ed25519 (`alg: EdDSA`), public key via JWKS
- **Refresh tokens** with rotation and theft detection (in memory)
- `/verify` endpoint for nginx `auth_request`
- Users, roles, claims and allowed redirects in **one TOML file**, reloaded without restart
- CLI to manage users and redirects

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

A systemd unit is in [examples/bfloginauth.service](examples/bfloginauth.service).
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

### Access token

```json
{ "iss": "https://example.com/login", "sub": "benno", "aud": "app1",
  "iat": …, "nbf": …, "exp": …, "jti": "…", "roles": ["admin"], …claims }
```

Backends can verify the token themselves with the key from `/login/.well-known/jwks.json` (OKP/Ed25519).
Server metadata is available at `/login/.well-known/oauth-authorization-server`.

## nginx

There are two options:

- **Snippets** to `include`, in [nginx/snippets/](nginx/snippets/) (e.g. copy them to `/etc/nginx/snippets/`):

  | File | Include in | Purpose |
  |---|---|---|
  | `bfloginauth-login-server.conf` | `server {}` of the login domain | Expose the login server under `/login/` |
  | `bfloginauth-verify-endpoint.conf` | every `server {}` with protected locations | Internal token check `/login/_auth-verify` |
  | `bfloginauth-verify.conf` | `location {}` | Require a valid token and one of the roles in `$bfloginauth_roles` (`""` = any valid token) |

  ```nginx
  server {
      server_name example.com;
      include snippets/bfloginauth-login-server.conf;
      include snippets/bfloginauth-verify-endpoint.conf;

      location /teacher/ {
          include snippets/bfloginauth-verify.conf;
          proxy_pass http://127.0.0.1:3000/;
      }
  }

  server {
      server_name app.example.com;
      include snippets/bfloginauth-verify-endpoint.conf;

      location / {
          set $bfloginauth_roles "";          # any valid token
          auth_request /login/_auth-verify;
          proxy_pass http://127.0.0.1:9000/;
      }
  }
  ```

  Set the roles in the location, never at `server {}` level: that would also run during the
  internal check and clear the roles.
- **Complete example config:** [examples/nginx.conf](examples/nginx.conf).

Short version without snippets:

```nginx
location = /login/_auth-verify {
    internal;
    set $bfloginauth_roles $bfloginauth_roles;
    uninitialized_variable_warn off;
    proxy_pass http://127.0.0.1:8080/verify?role=$bfloginauth_roles;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Authorization $http_authorization;
}
location /teacher/ {
    set $bfloginauth_roles "teacher,admin";   # "" = any valid token
    auth_request /login/_auth-verify;
    proxy_pass http://127.0.0.1:3000/;
}
```

`/verify` reads only `Authorization: Bearer …` and answers `200` (headers `X-Auth-User`, `X-Auth-Roles`),
`401`, or `403` (role missing). Removed or disabled users get `401` immediately, even if their token has not expired.

## Endpoints

nginx exposes the server under `/login/` and strips the prefix
(see [bfloginauth-login-server.conf](nginx/snippets/bfloginauth-login-server.conf)).
Set `issuer` to the public URL including the prefix, e.g. `https://example.com/login`.

| Method | Public path | Purpose |
|---|---|---|
| GET/POST | `/login/authorize` | Login page / login |
| POST | `/login/token` | `grant_type=authorization_code`: exchange a code<br>`grant_type=refresh_token`: get new tokens<br>`grant_type=revoke`: log out |
| GET | `/login/.well-known/jwks.json` | Public key |
| GET | `/login/.well-known/oauth-authorization-server` | Metadata |

Internal only (not reachable from outside): `/verify`, called by nginx `auth_request`.

## Limitations

- Refresh tokens and codes are kept in memory. After a restart, everyone has to log in again.
- The login server keeps no session (no SSO): every `/authorize` request shows the login form.
- Changes to `listen` and `key_file` take effect only after a restart.
- Single instance only (no shared state between processes).

## License

MIT, © 2026 Benjamin Benno Falkner. See [LICENSE](LICENSE).
