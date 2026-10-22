import express from 'express';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import config from '../config';
import * as userController from '../controllers/user/user.controller';
import { errorResponse, publicUser, signToken, successResponse } from '../helpers';

const router = express.Router();

const googleConfigured = Boolean(config.google.clientId && config.google.clientSecret);

if (googleConfigured) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: config.google.clientId,
        clientSecret: config.google.clientSecret,
        callbackURL: config.google.callbackUrl,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          return done(null, await userController.findOrCreateGoogleUser(profile));
        } catch (err) {
          return done(err);
        }
      },
    ),
  );
}

const requireGoogle = (req, res, next) =>
  googleConfigured ? next() : errorResponse(req, res, 'Google sign-in is not configured', 503);

router.get(
  '/google',
  requireGoogle,
  passport.authenticate('google', { scope: ['profile', 'email'], session: false }),
);

router.get(
  '/google/callback',
  requireGoogle,
  passport.authenticate('google', { session: false, failureRedirect: '/oauth/google/failure' }),
  (req, res) => {
    const token = signToken(req.user);
    if (config.google.clientRedirect) {
      // Fragment, not query string, so the token stays out of server logs.
      return res.redirect(`${config.google.clientRedirect}#token=${encodeURIComponent(token)}`);
    }
    return successResponse(req, res, { user: publicUser(req.user), token });
  },
);

router.get('/google/failure', (req, res) => errorResponse(req, res, 'Google sign-in failed', 401));

module.exports = router;
