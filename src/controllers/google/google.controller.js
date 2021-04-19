/** CONFIGURATION **/
const {google} = require('googleapis');

const url = require('url');
require("dotenv").config();
/*******************/
/*******************/

const googleConfig = {
    clientId: process.env.GOOGLE_CLIENT_ID, // e.g. asdfghjkljhgfdsghjk.apps.googleusercontent.com
    clientSecret: process.env.GOOGLE_CLIENT_SECRET, // e.g. _ASDFA%DFASDFASDFASD#FAD-
    redirect: process.env.GOOGLE_REDIRECT_URL, // this must match your google api settings
};

const defaultScope = [
    'https://www.googleapis.com/auth/plus.me',
    'https://www.googleapis.com/auth/userinfo.email',
];

/*************/
/** HELPERS **/

/*************/

function createConnection() {
    return new google.auth.OAuth2(
        googleConfig.clientId,
        googleConfig.clientSecret,
        googleConfig.redirect
    );
}

function getConnectionUrl(auth) {
    return auth.generateAuthUrl({
        access_type: 'offline',
        prompt: 'consent',
        scope: defaultScope
    });
}

function getGooglePlusApi(auth) {
    return google.plus({version: 'v1', auth});
}

/**********/
/** MAIN **/

/**********/

/**
 * Part 1: Create a Google URL and send to the client to log in the user.
 */
export function urlGoogle(req, res) {
    // console.log(process.env.GOOGLE_CLIENT_ID)
    const auth = createConnection();
    const url = getConnectionUrl(auth);
    return res.send({url});
}

/**
 * Part 2: Take the "code" parameter which Google gives us once when the user logs in, then get the user's email and id.
 */
export async function getGoogleAccountFromCode(req, res, next) {
    try {
        const code = url.parse(req.url, true).query;
        const auth = createConnection();
        const data = await auth.getToken(code);
        const tokens = data.tokens;
        auth.setCredentials(tokens);
        // const plus = getGooglePlusApi(auth);
        // const me = await plus.people.get({userId: 'me'});
        // const userGoogleId = me.data.id;
        // const userGoogleEmail = me.data.emails && me.data.emails.length && me.data.emails[0].value;
        return res.send(tokens);
    } catch (err) {
        return res.status(500).json({
            code: 500,
            errorMessage: 'Something went wrong',
            error: err.message,
            data: null,
            success: false
        })
    }
}
