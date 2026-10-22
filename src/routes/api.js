import express from 'express';
import * as userController from '../controllers/user/user.controller';

const router = express.Router();

// Every route here runs behind apiAuth, so req.user is the signed-in user.
router.get('/me', userController.me);
router.post('/changePassword', userController.changePassword);

module.exports = router;
