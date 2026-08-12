import express from 'express';
import { listUsers, getUserById } from '../controllers/userController.js';
import { protect, requireRole } from '../middleware/auth.js';
import { requireOrganizationIdentity } from '../middleware/organizationScope.js';
import { USER_ROLES } from '../models/User.js';

const router = express.Router();

router.use(protect);
router.use(requireRole([USER_ROLES.OWNER, USER_ROLES.REVIEWER]));
router.use(requireOrganizationIdentity);

router.get('/', listUsers);
router.get('/:id', getUserById);

export default router;
