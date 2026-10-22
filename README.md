# aspiration-server

A self-hosted authentication server you run next to your app, in one container, owning your own user data.

aspiration-server is an alternative to Auth0, Clerk and Firebase Auth for teams who want to self-host. It handles sign-up, sign-in, social login, email verification, password reset and sessions, and it signs short-lived JWTs that any backend verifies through standard JWKS. There is no vendor to call at runtime, no shared secret to distribute, and no per-user pricing. You run it, you own the database, and you can be **set up and running in under 10 minutes**.

It is built for developers who want a single, auditable auth service: one Node process, a Postgres database in production (or zero-setup SQLite for local dev), and a public key your other services trust.

## Features

- **Email and password** sign-in, with passwords hashed using **Argon2id** (OWASP parameters).
- **Email verification** and **password reset** flows (SMTP), with links that expire and are single-use.
- **Social sign-in** with Google, GitHub and Apple. Google and Apple work natively on mobile via an ID token; Google and GitHub work on the web via a redirect flow.
- **Short-lived RS256 access tokens** (JWTs) published through **JWKS**, so any backend in any language verifies them locally with no shared secret and no call back to the auth server.
- **Rotating refresh tokens** with reuse detection: a stolen-and-reused token revokes the whole token family.
- **Account lockout** after repeated failed sign-ins, plus per-IP and per-email **rate limiting**.
- **Sessions list** and **sign-out everywhere**, so users can see and end their logins on other devices.
- **Self-service account deletion**, as required by the App Store and GDPR.
- **Admin user management**: list, inspect, change roles and delete users.
- **Signed webhooks** on `user.created` and `user.deleted`.
- A **JavaScript SDK** for browser and Node apps.

## Quick start (under 10 minutes)

### With Docker (Postgres included)

```bash
git clone https://github.com/Mishallic/aspiration-server.git
cd aspiration-server
cp example.env .env
docker compose up
```

The server comes up at **http://localhost:8080** with a Postgres database wired in by the compose file. Nothing else to install or configure. Migrations run automatically on start.

### With local Node (zero config)

Requires Node 22+.

```bash
npm install
npm start
```

The server starts at **http://localhost:8080**. With no `DATABASE_URL` set it uses a local SQLite file (`./data/auth.sqlite`), so there is no database to set up for development.

### Try it with curl

Sign up a user:

```bash
curl -s -X POST http://localhost:8080/v1/auth/signup \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"correct-horse-battery-staple"}'
```

The response includes the new user, an `accessToken` and a `refreshToken`:

```json
{
  "user": { "id": "...", "email": "you@example.com", "role": "user", "emailVerified": false },
  "accessToken": "eyJhbGciOiJSUzI1Ni...",
  "refreshToken": "rt_...",
  "expiresIn": 900
}
```

Call an authenticated endpoint with the access token:

```bash
curl -s http://localhost:8080/v1/me \
  -H 'authorization: Bearer <accessToken>'
```

### Make a user an admin

With Docker:

```bash
docker compose exec app node src/cli.js make-admin you@example.com
```

Without Docker:

```bash
node src/cli.js make-admin you@example.com
```

The user's role becomes `admin` and their existing sessions are signed out so the new role takes effect on the next sign-in.

## How token verification works

The auth server holds a **private RS256 key** and signs every access token with it. It publishes the matching **public key** at `/.well-known/jwks.json`.

Your other backends never share a secret with the auth server and never call it to check a token. They fetch the JWKS once, cache it, and verify tokens locally. Any language with a JWT library can do this. Verification checks the signature, the issuer (`PUBLIC_URL`) and the audience (`JWT_AUDIENCE`, which defaults to `app`).

Here is a Node example using `jose`:

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';

const PUBLIC_URL = 'https://auth.example.com';
const JWKS = createRemoteJWKSet(new URL(`${PUBLIC_URL}/.well-known/jwks.json`));

export async function verifyToken(token) {
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: PUBLIC_URL,
    audience: 'app', // JWT_AUDIENCE
  });
  return payload;
}
```

Access tokens carry these claims:

| Claim | Meaning |
| --- | --- |
| `sub` | User id |
| `email` | User email |
| `email_verified` | Whether the email is verified |
| `role` | `user` or `admin` |
| `iss`, `aud`, `iat`, `exp`, `jti` | Standard issuer, audience, issued-at, expiry and token id |

## Using the JavaScript SDK

The SDK lives in `sdk/` (import path `sdk/index.js`). It has no dependencies and works in the browser and in Node.

```js
import { createAuthClient } from 'aspiration-server/sdk';

const auth = createAuthClient({ baseUrl: 'https://auth.example.com' });

await auth.signUp({ email: 'you@example.com', password: 'correct-horse-battery-staple' });
await auth.signIn({ email: 'you@example.com', password: 'correct-horse-battery-staple' });

const user = auth.getUser();

// Calls your own API with the bearer token attached, refreshing the access token automatically.
const res = await auth.fetchWithAuth('https://your-api.example.com/things');

await auth.signOut();
```

The SDK stores tokens for you (localStorage in the browser, in-memory in Node) and refreshes the access token automatically before it expires and once more if a `fetchWithAuth` call comes back `401`. Fuller SDK docs are in [`sdk/README.md`](sdk/README.md).

## API overview

All application endpoints are under `/v1`. Errors use a uniform shape:

```json
{ "error": { "code": "invalid_credentials", "message": "Incorrect email or password", "details": {} } }
```

`code` is stable and machine-readable; `message` is for humans. `details` is optional. The full specification is in [`openapi.yaml`](openapi.yaml).

### Auth

| Method | Path | Purpose | Bearer |
| --- | --- | --- | --- |
| POST | `/v1/auth/signup` | Create an account, return tokens | No |
| POST | `/v1/auth/login` | Sign in with email and password | No |
| POST | `/v1/auth/refresh` | Exchange a refresh token for a new token pair | No |
| POST | `/v1/auth/logout` | Revoke a refresh token | No |

### Email

| Method | Path | Purpose | Bearer |
| --- | --- | --- | --- |
| POST | `/v1/auth/verify-email` | Confirm an email with a token | No |
| POST | `/v1/auth/verify-email/resend` | Resend the verification email | No |
| POST | `/v1/auth/password/forgot` | Request a password reset email | No |
| POST | `/v1/auth/password/reset` | Set a new password with a reset token | No |

### OAuth

| Method | Path | Purpose | Bearer |
| --- | --- | --- | --- |
| GET | `/v1/auth/oauth/providers` | List configured providers and their modes | No |
| POST | `/v1/auth/oauth/{provider}/native` | Native sign-in with a provider ID token | No |
| GET | `/v1/auth/oauth/{provider}/start` | Begin the web redirect flow | No |
| GET | `/v1/auth/oauth/{provider}/callback` | Provider redirect target | No |
| POST | `/v1/auth/oauth/exchange` | Trade a one-time app code for tokens | No |

### Account

| Method | Path | Purpose | Bearer |
| --- | --- | --- | --- |
| GET | `/v1/me` | Get the current user | Yes |
| PATCH | `/v1/me` | Update the current user's profile | Yes |
| DELETE | `/v1/me` | Delete the current account | Yes |
| POST | `/v1/me/change-password` | Change the password | Yes |
| GET | `/v1/me/sessions` | List active sessions | Yes |
| POST | `/v1/me/logout-all` | Sign out of every session | Yes |

### Admin

| Method | Path | Purpose | Bearer |
| --- | --- | --- | --- |
| GET | `/v1/admin/users` | List users (paged, searchable) | Yes (admin) |
| GET | `/v1/admin/users/{id}` | Get one user | Yes (admin) |
| PATCH | `/v1/admin/users/{id}/role` | Change a user's role | Yes (admin) |
| DELETE | `/v1/admin/users/{id}` | Delete a user | Yes (admin) |

### Discovery

| Method | Path | Purpose | Bearer |
| --- | --- | --- | --- |
| GET | `/health` | Liveness and database check | No |
| GET | `/.well-known/jwks.json` | Public signing keys (JWKS) | No |
| GET | `/.well-known/openid-configuration` | Issuer and JWKS metadata | No |

## Configuration

Configuration comes from environment variables. It is **validated at startup**, and the server **refuses to start on unsafe production settings** (for example an `http` `PUBLIC_URL` in production, or a `WEBHOOK_URL` without a sufficiently long `WEBHOOK_SECRET`).

### Core

| Variable | What it does | Default | Required in prod |
| --- | --- | --- | --- |
| `NODE_ENV` | `development`, `test` or `production` | `development` | Recommended |
| `PORT` | Port to listen on | `8080` | No |
| `PUBLIC_URL` | Public base URL; also the JWT issuer | `http://localhost:8080` | Yes (https) |
| `DATABASE_URL` | Database connection string | SQLite file `./data/auth.sqlite` | Yes (Postgres) |
| `TRUST_PROXY` | Express trust-proxy setting (e.g. `1`) when behind a proxy | unset | If proxied |
| `CORS_ORIGINS` | Comma-separated allowed browser origins | empty | For browser apps |
| `APP_NAME` | App name used in emails | `Your app` | No |

### Tokens

| Variable | What it does | Default | Required in prod |
| --- | --- | --- | --- |
| `JWT_AUDIENCE` | Audience claim your backends check | `app` | No |
| `ACCESS_TOKEN_TTL_SECONDS` | Access token lifetime in seconds (60–86400) | `900` | No |
| `REFRESH_TOKEN_TTL_DAYS` | Refresh token lifetime in days (1–365) | `30` | No |
| `SIGNING_KEY` | Pinned RS256 private key (PEM). If unset, a key is generated and persisted in the DB | unset | Optional |

### Email / SMTP

| Variable | What it does | Default | Required in prod |
| --- | --- | --- | --- |
| `REQUIRE_EMAIL_VERIFICATION` | Require a verified email before sign-in | `false` | No |
| `SMTP_URL` | SMTP connection URL for sending email | unset | To send email |
| `EMAIL_FROM` | From header on outgoing email | `Auth <no-reply@localhost>` | No |
| `PASSWORD_RESET_URL` | Front-end URL that handles reset links | unset | No |
| `EMAIL_VERIFIED_REDIRECT_URL` | Where to send users after verifying | unset | No |

### OAuth providers

Set credentials only for the providers you use. Google and GitHub each require their id and secret to be set together.

| Variable | What it does | Default | Required in prod |
| --- | --- | --- | --- |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google web OAuth credentials (set together) | unset | For Google web |
| `GOOGLE_NATIVE_CLIENT_IDS` | Comma-separated Google client IDs accepted for native ID tokens | empty | For Google mobile |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub web OAuth credentials (set together) | unset | For GitHub web |
| `APPLE_CLIENT_IDS` | Comma-separated Apple client IDs accepted for native ID tokens | empty | For Apple mobile |

For **web** sign-in, register this redirect/callback URI with the provider:

```
${PUBLIC_URL}/v1/auth/oauth/{provider}/callback
```

and register each allowed client return URL in `ALLOWED_REDIRECT_URLS` (see below). For **native** sign-in, the mobile app obtains the ID token through the provider SDK and posts it; the client IDs it uses must be listed in `GOOGLE_NATIVE_CLIENT_IDS` / `APPLE_CLIENT_IDS`.

### Redirects, webhooks and rate limiting

| Variable | What it does | Default | Required in prod |
| --- | --- | --- | --- |
| `ALLOWED_REDIRECT_URLS` | Comma-separated allowlist of OAuth client return URLs | empty | For OAuth web |
| `WEBHOOK_URL` | URL to receive signed `user.created` / `user.deleted` events | unset | No |
| `WEBHOOK_SECRET` | Secret used to sign webhooks; min 24 chars, required when `WEBHOOK_URL` is set | unset | With webhooks |
| `RATE_LIMIT_ENABLED` | Toggle built-in rate limiting | `true` | No |

## Security

- Passwords are hashed with **Argon2id** using OWASP-recommended parameters.
- Refresh tokens and one-time tokens are stored only as **SHA-256 hashes**, never in plaintext.
- **Refresh-token rotation** with reuse detection: reusing a rotated token revokes the entire token family.
- **Account lockout** after repeated failed sign-ins, with a timed unlock.
- **Rate limiting** per IP and per email address, so no single address or inbox can be flooded.
- OAuth uses a **redirect allowlist**, a **single-use state token** and a **one-time app code**; no tokens are ever placed in redirect URLs.
- Accounts are linked to a provider only on a **provider-verified email**.
- **helmet** security headers; **secure cookies** are set automatically when `PUBLIC_URL` is https.
- **Uniform responses** that never reveal whether an email is registered (resend, forgot-password and logout always succeed).
- **Startup config validation** blocks unsafe production settings before the server accepts traffic.

Signing keys live in the database. Rotate them without downtime:

```bash
node src/cli.js rotate-key
```

The old key stays published in the JWKS until the next rotation, so tokens signed with it keep verifying. Alternatively, pin a fixed key with the `SIGNING_KEY` environment variable.

## Running in production

- Use **Postgres**: set `DATABASE_URL` to your connection string.
- Set a strong `SIGNING_KEY`, or let the server generate one and persist it in the database.
- Set `PUBLIC_URL` to your public **https** URL (the server refuses an `http` URL in production).
- Set `CORS_ORIGINS` to your front-end origins and `ALLOWED_REDIRECT_URLS` to your OAuth return URLs.
- Terminate **TLS** in front of the server, and set `TRUST_PROXY` when it runs behind a reverse proxy or load balancer.
- Migrations run automatically on start (Umzug). You can also run them manually with `npm run migrate`.

## Tests

```bash
npm test     # vitest
npm run lint # eslint
```

The suite covers the email/password flows, refresh-token rotation and reuse detection, OAuth (with stubbed providers), rate limiting and account lockout, and verification of issued tokens through JWKS exactly as a third-party backend would.

## Project layout

```
src/
  config.js       Environment parsing and production safety checks
  server.js       Process entry point: load config, build app, listen
  app.js          Express app: middleware, routes, error handling
  context.js      Wires config, database, services and rate limits together
  cli.js          Admin CLI: migrate, make-admin, remove-admin, rotate-key
  db/             Sequelize setup, models and Umzug migrations
  lib/            Crypto, password hashing, errors, validation, user helpers
  services/       Sessions, keys, accounts, email flows, OAuth, webhooks, mailer
  routes/         HTTP route handlers per area
  middleware/     Auth, rate limiting and error middleware
  pages/          Minimal HTML pages for email links
sdk/              JavaScript client (createAuthClient)
tests/            vitest suite
openapi.yaml      Full API specification
Dockerfile        Container image
docker-compose.yml  App plus Postgres for local and simple deploys
```

## License

ISC.
