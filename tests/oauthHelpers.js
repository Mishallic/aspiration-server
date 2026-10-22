import { SignJWT, exportJWK, generateKeyPair } from 'jose';

// Builds a fake provider: a key pair whose public JWK is served at the provider's
// JWKS URL, plus a signer for ID tokens. Lets the OAuth paths run fully offline.
export async function makeFakeProvider({ jwksUrl, issuer }) {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' };

  async function idToken(claims, { aud, iss = issuer } = {}) {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(iss)
      .setAudience(aud)
      .setSubject(claims.sub)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
  }

  return { jwksUrl, jwks: { keys: [jwk] }, idToken };
}

const jsonResponse = (body, ok = true, status = 200) => ({
  ok,
  status,
  json: async () => body,
});

// A fetch stub routed by URL. `routes` maps a matcher to a handler returning a body
// (wrapped as a JSON response) or a full response object. Records every call.
export function stubFetch(routes) {
  const calls = [];
  const impl = async (url, init = {}) => {
    const href = typeof url === 'string' ? url : url.url;
    calls.push({ href, init });
    for (const [match, handler] of routes) {
      if (href.startsWith(match)) {
        const result = await handler(href, init);
        if (result && typeof result.json === 'function') return result;
        return jsonResponse(result);
      }
    }
    throw new Error(`Unexpected fetch to ${href}`);
  };
  impl.calls = calls;
  return impl;
}

export { jsonResponse };
