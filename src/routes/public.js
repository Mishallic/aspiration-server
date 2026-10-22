import express from 'express';
import * as userController from '../controllers/user/user.controller';

const router = express.Router();

router.get('/PING', (req, res) => res.send('PONG'));
router.post('/user/register', userController.register);
router.post('/user/login', userController.login);

module.exports = router;
