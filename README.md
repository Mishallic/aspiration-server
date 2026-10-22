# aspiration-server

An authentication API for a mobile or web client. Users sign up with email and password or with Google, get a JSON Web Token (JWT), and use it to reach protected routes. Admins can page through all users.

Built with Express 5 and Sequelize. It runs on SQLite with zero setup, and on MySQL or Postgres in production.

## What it does

- **Email and password accounts.** Register, log in, change password. Passwords are hashed with bcrypt.
- **Google sign-in.** The OAuth flow creates the account on first sign-in, or links Google to an existing account with the same email.
- **JWT sessions.** Login and Google sign-in both return a signed token that expires after 7 days by default. Clients send it in the `x-token` header.
- **Admin listing.** Admins can page through users. Password hashes and verify tokens never leave the server.
- **Consistent errors.** Every response has the same JSON shape and a real HTTP status code.

## How it works

```
client ── POST /pub/user/login ──▶ bcrypt check ──▶ JWT { userId, email }
client ── GET /api/me + x-token ─▶ apiAuth: verify JWT, load user ──▶ handler
client ── GET /oauth/google ─────▶ Google consent ──▶ /oauth/google/callback
                                   find or create user ──▶ JWT (JSON or redirect)
```

`apiAuth` verifies the token, then reloads the user from the database on every request. A deleted user's token stops working immediately, and an admin flag change takes effect on the next request.

On start, the server calls `sequelize.sync()`, which creates the `user` table if it is missing.

## Architecture

```
index.js                      bootstrap: connect DB, sync, listen
src/
  app.js                      Express app (no listen, so tests import it)
  config.js                   every environment variable, with defaults
  models/index.js             Sequelize setup: SQLite, MySQL or Postgres
  models/user.js              User model; secrets hidden by default scope
  helpers/index.js            responses, bcrypt, JWT, validation
  middleware/apiAuth.js       JWT check, sets req.user
  middleware/adminAuth.js     403 unless req.user.isAdmin
  middleware/errorHandler.js  JSON 404 and error responses
  controllers/user/           register, login, me, changePassword, allUsers, Google users
  routes/                     public, api, admin, oauth routers
tests/                        Jest + Supertest, in-memory SQLite
```

Source files use ES module syntax compiled by Babel at runtime through `@babel/register`, as the original project did.

## API

All JSON responses share one shape:

```json
{ "code": 200, "success": true, "data": { } }
{ "code": 401, "success": false, "data": null, "errorMessage": "Token is not provided" }
```

| Method | Path | Auth | Body or query | Success |
| --- | --- | --- | --- | --- |
| GET | `/pub/PING` | none | | `PONG` as text |
| POST | `/pub/user/register` | none | `email`, `password` (8+ chars), optional `firstName`, `lastName` | 201, `{ user }` |
| POST | `/pub/user/login` | none | `email`, `password` | 200, `{ user, token }` |
| GET | `/api/me` | `x-token` | | 200, `{ user }` |
| POST | `/api/changePassword` | `x-token` | `oldPassword`, `newPassword` (8+ chars) | 200 |
| GET | `/api/admin/allUsers` | `x-token`, admin | `?page=1&limit=20` (max 100) | 200, `{ users, page, limit, total, totalPages }` |
| GET | `/oauth/google` | none | | redirect to Google |
| GET | `/oauth/google/callback` | Google | | 200 `{ user, token }`, or redirect to `CLIENT_OAUTH_REDIRECT#token=…` |

Error codes:

| Status | When |
| --- | --- |
| 400 | Missing or invalid fields, malformed JSON |
| 401 | No token, bad or expired token, wrong credentials |
| 403 | Signed in but not an admin |
| 404 | Unknown route |
| 409 | Email already registered |
| 503 | Google sign-in called while it is not configured |

Emails are stored lowercase, so login and duplicate checks ignore case. Login returns the same message for an unknown email and a wrong password, so it cannot be used to discover which emails are registered.

### Example session

```bash
curl -X POST localhost:8080/pub/user/register -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","password":"analytical-engine"}'

TOKEN=$(curl -s -X POST localhost:8080/pub/user/login -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","password":"analytical-engine"}' | jq -r .data.token)

curl localhost:8080/api/me -H "x-token: $TOKEN"
```

To make a user an admin, set the `isAdmin` column to true in the database. There is deliberately no API for it.

## Tests

```bash
npm test
```

62 tests across 6 suites run against an in-memory SQLite database, so they need no setup:

- **app**: health check, JSON 404 for unknown routes, 400 for malformed JSON.
- **responses**: helpers send the status they are given, 500s hide internals, client errors keep their message.
- **helpers**: bcrypt hashing and salting, JWT round trip, expiry and forgery, email validation, secret stripping.
- **auth**: register validation and duplicates, case-insensitive email, no self-assigned admin, login, `/api/me`, forged, expired and deleted-user tokens, the full change-password flow.
- **admin**: 401 and 403 gates, pagination and page-size cap, no secrets in the listing.
- **oauth**: Google user creation, repeat sign-in, account linking, missing email, 503 when Google is not configured.

## What changed from the 2021 version

The 2021 code had these defects, each now covered by a test:

- **`/pub/user/me` handed out a valid token for any user id**, with no authentication. It is replaced by the authenticated `GET /api/me`.
- **Passwords were hashed with unsalted MD5.** They now use bcrypt.
- **`changePassword` always crashed** with a `ReferenceError`, because it read `oldPassword` and `newPassword` as undefined variables.
- **Every error returned HTTP 500**, including bad logins and missing tokens, because the error helper ignored its status argument.
- **Admin pagination never worked**, because it read `req.params.page` on a route with no page parameter, with a page size of 2.
- **Google sign-in issued no token.** It redirected with the raw Google id, which the client then traded at the open `/me` endpoint. The callback now issues a JWT itself.
- **Tokens never expired.** They now expire after 7 days by default.
- **`login` answered Google users with HTTP 306**, a status code that is reserved and unused.

Also removed: the unused `googleapis` flow built on the retired Google+ API, the commented-out proxy, `stresstest.js` (which fired 100 requests at a hardcoded public IP), an empty migration, and the `fs` and `path` npm packages, which shadow Node built-ins. Dependencies were upgraded, including Express 4 to 5, jsonwebtoken 8 to 9, mysql2 2 to 3 and Sequelize 6.6 to 6.37.

## Limits

- **Schema management uses `sync()`**, which creates missing tables but does not alter existing ones. A production database with real data should move to Sequelize migrations before the schema changes.
- **Accounts created before this version cannot log in.** Their MD5 hashes are not bcrypt hashes. They need a password reset, and there is no reset flow yet.
- **Logout is client-side.** JWTs are stateless, so a stolen token works until it expires. Shorten `JWT_EXPIRES_IN` if that matters.
- **No rate limiting.** Put the server behind a proxy that rate-limits `/pub/user/login`, or add `express-rate-limit`.
- **One dev-only audit warning remains**, in `sprintf-js` inside Jest's coverage tooling. It has no upstream fix and does not ship. Production dependencies audit clean.

## Deliberately left out

- **Email verification and password reset.** The model has `isVerified` and `verifyToken`, but sending email needs a mail provider and a client screen to land on.
- **Refresh tokens.** One token with an expiry is enough for this scope.
- **The mobile client.** The original app is not in this repository or any other, so the API was kept close to its 2021 shape. The two changes a client would notice are `/api/me` replacing `/pub/user/me` and Google sign-in returning a token.
- **A public deployment.** There is no client to use it, so the target is a server that runs locally with zero setup.

## Run locally

Requires Node 20 or newer.

```bash
npm install
cp example.env .env   # optional; defaults work for local use
npm run dev           # restarts on file changes
# or
npm start
```

The server listens on `http://localhost:8080` and stores data in `./dev.sqlite`.

To enable Google sign-in, create an OAuth client in Google Cloud Console and add `http://localhost:8080/oauth/google/callback` as an authorized redirect URI. Then set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env`.

## Deploy

The server is a long-running Node process, so it suits Render, Railway, Fly.io or a VPS rather than serverless hosting.

1. Create a Postgres or MySQL database.
2. Set `NODE_ENV=production`, a long random `SECRET`, `CORS_ORIGIN` set to your client's origin, and either `DB_CONNECTION_STRING` with `DB_DIALECT`, or the separate `DB_*` fields. The server refuses to start in production without `SECRET`.
3. For Google sign-in, set the `GOOGLE_*` variables, with `GOOGLE_CALLBACK_URL` pointing at the public `/oauth/google/callback`, and register that URL with Google.
4. Run `npm ci --omit=dev && npm start`.

See `example.env` for every variable.
