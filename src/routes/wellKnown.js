import express from 'express';
import { SIGNING_ALG } from '../services/keys.js';

// Standard discovery endpoints, so off-the-shelf JWT libraries can find the keys.
export function wellKnownRoutes({ config, services }) {
  const router = express.Router();

  router.get('/.well-known/jwks.json', (req, res) => {
    res.set('Cache-Control', 'public, max-age=300').json(services.keys.jwks());
  });

  router.get('/.well-known/openid-configuration', (req, res) => {
    res.set('Cache-Control', 'public, max-age=3600').json({
      issuer: config.jwt.issuer,
      jwks_uri: `${config.publicUrl}/.well-known/jwks.json`,
      id_token_signing_alg_values_supported: [SIGNING_ALG],
      token_endpoint: `${config.publicUrl}/v1/auth/refresh`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
    });
  });

  return router;
}
