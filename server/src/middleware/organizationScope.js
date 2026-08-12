function normalizeId(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'object' && value._id !== undefined) return normalizeId(value._id);
  if (typeof value.toString === 'function') return value.toString();
  return String(value);
}

export function getAuthenticatedOrganizationId(req) {
  return normalizeId(req?.user?.organizationId);
}

export function getResourceOrganizationId(resource) {
  return normalizeId(resource?.organizationId);
}

export function requireOrganizationIdentity(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ success: false, message: 'Authentication is required' });
  }

  if (!getAuthenticatedOrganizationId(req)) {
    return res.status(401).json({ success: false, message: 'Authenticated organization identity is required' });
  }

  return next();
}

export function assertSameOrganization(req, resource) {
  const authenticatedOrganizationId = getAuthenticatedOrganizationId(req);
  if (!authenticatedOrganizationId) {
    return { allowed: false, statusCode: 401, message: 'Authenticated organization identity is required' };
  }

  const resourceOrganizationId = getResourceOrganizationId(resource);
  if (!resourceOrganizationId) {
    return { allowed: false, statusCode: 403, message: 'Resource organization identity is required' };
  }

  if (resourceOrganizationId !== authenticatedOrganizationId) {
    return { allowed: false, statusCode: 403, message: 'Cross-organization access is forbidden' };
  }

  return { allowed: true, organizationId: authenticatedOrganizationId };
}

export function requireSameOrganization(resolveResource) {
  if (typeof resolveResource !== 'function') {
    throw new TypeError('requireSameOrganization requires a resource resolver function');
  }

  return async function organizationResourceIsolation(req, res, next) {
    try {
      const resource = await resolveResource(req, res);
      const result = assertSameOrganization(req, resource);

      if (!result.allowed) {
        return res.status(result.statusCode).json({ success: false, message: result.message });
      }

      req.organizationId = result.organizationId;
      req.resource = resource;
      return next();
    } catch (error) {
      return next(error);
    }
  };
}

export function scopeToAuthenticatedOrganization(req, extraFilter = {}) {
  const organizationId = getAuthenticatedOrganizationId(req);
  if (!organizationId) {
    throw Object.assign(new Error('Authenticated organization identity is required'), { statusCode: 401 });
  }

  return { ...extraFilter, organizationId };
}
