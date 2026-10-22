import express from 'express';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import config from '../config';
import * as userController from '../controllers/user/user.controller';

const router = express.Router();

passport.serializeUser((user, done) => {
    done(null, user);
})

passport.deserializeUser((user, done) => {
    done(null, user)
})

// Register the strategy only when credentials exist, so the server can
// start without Google configured.
if (config.google.clientId && config.google.clientSecret) {
    passport.use(new GoogleStrategy({
        clientID: config.google.clientId,
        clientSecret: config.google.clientSecret,
        callbackURL: config.google.callbackUrl,
    }, async (accessToken, refreshToken, profile, done) => {
        await userController.oauthLog(profile)
        done(null, profile, accessToken)
    }))
}

router.get('/google', passport.authenticate('google', {
    scope: ['profile', 'email'],
}));

router.get('/google/callback', passport.authenticate('google'), (req, res) => {
    res.redirect('/pub/PING');
});

module.exports = router
