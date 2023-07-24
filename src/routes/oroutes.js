import passport from "passport";
import express from "express";
const GoogleStrategy = require('passport-google-oauth20').Strategy;

import * as googleController from "../controllers/google/google.controller";
import * as userController from "../controllers/user/user.controller";

const router = express.Router();

passport.serializeUser((user, done) => {
    done(null, user);
})

passport.deserializeUser((user, done) => {
    done(null, user)
})

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:8080/oauth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
    await userController.oauthLog(profile)
    done(null, profile,accessToken)
}))

router.get('/google', (req, res, next) => {
    next()
});
router.get('/google', passport.authenticate('google', {
    scope: ['profile', 'email'],
}));

router.get('/google/callback', passport.authenticate('google'), (req, res, next) => {
    // res.redirect("msrm42app://msrm42app.io?googleId=" + req.user.id);
    res.redirect("http://localhost:8080/pub/ping");
});

router.get('/oauth-google', googleController.urlGoogle)

router.get('/google-auth-code', googleController.getGoogleAccountFromCode)


module.exports = router
