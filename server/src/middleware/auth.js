import mongoose from 'mongoose';

function unauthorized(message = 'Authentication required') {
  const err = new Error(message);
  err.status = 401;
  return err;
}

export function requireAuth(req, res, next) {
  const userId = req.header('x-user-id');
  const organizationId = req.header('x-organization-id');
  const role = req.header('x-user-role') || 'MEMBER';

  if (!userId || !organizationId) return next(unauthorized());
  if (!mongoose.isValidObjectId(userId) || !mongoose.isValidObjectId(organizationId)) {
    return next(unauthorized('Invalid authentication context'));
  }

  req.user = { userId, organizationId, role };
  return next();
}
