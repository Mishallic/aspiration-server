import express from 'express';
import * as userController from '../controllers/user/user.controller';

const router = express.Router();

//= ===============================
// API routes
//= ===============================
router.post('/changePassword', userController.changePassword);

module.exports = router;
