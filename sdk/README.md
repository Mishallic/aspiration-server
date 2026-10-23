# aspiration-server JavaScript SDK

A tiny, dependency-free client for [aspiration-server](../README.md). Works in the browser
and in Node 18+. It stores the session, refreshes the access token automatically, and
attaches it to requests to your own API.

## Install

The SDK is one file, `sdk/index.js`, shipped with the server. Copy it into your app, or
import it from the package:

```js
import { createAuthClient } from 'aspiration-server/sdk';
```

## Create a client

```js
const auth = createAuthClient({ baseUrl: 'https://auth.example.com' });
```

Options:

| Option | Default | Purpose |
| --- | --- | --- |
| `baseUrl` | required | Base URL of your auth server. |
| `storage` | `localStorage`, else memory | Where the session is kept. Pass any `{getItem,setItem,removeItem}`. |
| `fetch` | global `fetch` | Override the fetch implementation. |

In the browser the session persists in `localStorage`. In Node it lives in memory unless
you pass a `storage` object.

## Email and password

```js
await auth.signUp({ email, password, firstName });   // creates the account, signs in
await auth.signIn({ email, password });              // signs in
auth.getUser();                                       // { id, email, role, ... } or null
auth.isAuthenticated();                               // boolean
await auth.signOut();                                 // clears the session, revokes the token
```

`signUp` and `signIn` throw an `AuthError` (with `.status` and `.code`) on failure, for
example `{ status: 401, code: 'invalid_credentials' }`.

## Calling your own API

Use `fetchWithAuth` exactly like `fetch`. It adds the `Authorization: Bearer` header,
and if your API answers `401` it refreshes the token once and retries.

```js
const res = await auth.fetchWithAuth('https://api.example.com/orders');
const orders = await res.json();
```

Your API verifies the token itself against the server's JWKS (see the main README). The
SDK never sends your refresh token to your API, only the short-lived access token.

## Social sign-in

Native (mobile): sign in with the Google or Apple SDK, then pass the ID token:

```js
await auth.signInWithIdToken({ provider: 'google', idToken });
```

Web: send the user to the provider, then exchange the one-time code the server returns in
the redirect fragment (`#code=...`):

```js
location.href = auth.startWebSignIn('github', 'https://app.example.com/auth/callback');
// ...after the redirect back, read `code` from location.hash:
await auth.exchangeCode(code);
```

## Account management

```js
await auth.updateProfile({ firstName, lastName, avatarUrl });
await auth.changePassword({ currentPassword, newPassword });
await auth.listSessions();        // devices/sessions for this user
await auth.logoutEverywhere();    // revoke all sessions
await auth.deleteAccount();       // delete the account
```

## Password reset and verification

```js
await auth.requestPasswordReset(email);         // sends the email
await auth.resetPassword({ token, newPassword }); // token from the email link
await auth.verifyEmail(token);
await auth.resendVerification(email);
```

## React tip

`onAuthChange` fires whenever the user signs in or out:

```js
useEffect(() => auth.onAuthChange(setUser), []);
```
