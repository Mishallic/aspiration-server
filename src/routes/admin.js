import express from 'express';
import * as userController from '../controllers/user/user.controller';

const router = express.Router();

// Runs behind apiAuth and adminAuth. Supports ?page=&limit= query params.
router.get('/allUsers', userController.allUsers);

module.exports = router;
