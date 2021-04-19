import express from 'express';
import * as userController from '../controllers/user/user.controller';
import * as googleController from '../controllers/google/google.controller'


const router = express.Router();

router.get('/PING', (req, res) => {
    res.send('PONG')
})
router.post('/user/register', userController.register)
router.post('/user/login', userController.login)
router.get('/oauth-google', googleController.urlGoogle)
router.get('/google-auth-code', googleController.getGoogleAccountFromCode)
module.exports = router