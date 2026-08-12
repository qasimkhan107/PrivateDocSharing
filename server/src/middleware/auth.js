import jwt from 'jsonwebtoken';
import { USER_ROLE_VALUES } from '../models/User.js';

export function protect(req, res, next) {
  const authorization = req.get('authorization') || '';
  const [scheme, token] = authorization.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ success: false, message: 'Authentication token is required' });
  }

  const secret = process.env.JWT_SECRET;
  if (!secret) {
    return next(Object.assign(new Error('JWT_SECRET is not configured'), { statusCode: 500 }));
  }

  try {
    const payload = jwt.verify(token, secret);
    req.user = {
      userId: payload.userId,
      role: payload.role,
      organizationId: payload.organizationId,
    };
    return next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Invalid or expired authentication token' });
  }
}

export function requireRole(allowedRoles) {
  const normalizedAllowedRoles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
  const hasInvalidConfiguration =
    normalizedAllowedRoles.length === 0 ||
    normalizedAllowedRoles.some((role) => typeof role !== 'string' || !USER_ROLE_VALUES.includes(role));

  return function roleAuthorization(req, res, next) {
    if (hasInvalidConfiguration) {
      return next(Object.assign(new Error('Invalid role authorization configuration'), { statusCode: 500 }));
    }

    if (!req.user) {
      return res.status(401).json({ success: false, message: 'Authentication is required' });
    }

    if (!normalizedAllowedRoles.includes(req.user.role)) {
      return res.status(403).json({ success: false, message: 'Insufficient role permissions' });
    }

    return next();
  };
}
