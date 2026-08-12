import mongoose from 'mongoose';
import User from '../models/User.js';
import { assertSameOrganization, scopeToAuthenticatedOrganization } from '../middleware/organizationScope.js';
import { toSafeUser } from '../utils/auth.js';

export async function listUsers(req, res, next) {
  try {
    const users = await User.find(scopeToAuthenticatedOrganization(req)).sort({ createdAt: -1 });

    return res.json({
      success: true,
      users: users.map(toSafeUser),
    });
  } catch (error) {
    return next(error);
  }
}

export async function getUserById(req, res, next) {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }

    const user = await User.findById(id);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const organizationCheck = assertSameOrganization(req, user);
    if (!organizationCheck.allowed) {
      return res.status(organizationCheck.statusCode).json({
        success: false,
        message: organizationCheck.message,
      });
    }

    return res.json({
      success: true,
      user: toSafeUser(user),
    });
  } catch (error) {
    return next(error);
  }
}
