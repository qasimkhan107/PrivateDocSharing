import assert from 'node:assert/strict';
import test from 'node:test';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import { buildNewOrganizationOwnerInput } from '../controllers/authController.js';
import { protect, requireRole } from '../middleware/auth.js';
import User, { USER_ROLE_VALUES, USER_ROLES } from '../models/User.js';
import { generateToken, normalizeEmail, toSafeUser } from '../utils/auth.js';

function createMockResponse() {
  return {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
}

test('normalizeEmail trims and lowercases email addresses', () => {
  assert.equal(normalizeEmail('  Owner@Example.COM  '), 'owner@example.com');
});

test('bcrypt hashing stores a non-plaintext password and compare validates it', async () => {
  const plaintext = 'correct horse battery staple';
  const hash = await bcrypt.hash(plaintext, 12);

  assert.notEqual(hash, plaintext);
  assert.match(hash, /^\$2[aby]\$/);
  assert.equal(await bcrypt.compare(plaintext, hash), true);
  assert.equal(await bcrypt.compare('wrong password', hash), false);
});

test('safe user serialization never exposes password fields', () => {
  const safeUser = toSafeUser({
    _id: { toString: () => 'user-id' },
    name: 'Owner',
    email: 'owner@example.com',
    password: 'stored-hash',
    role: 'owner',
    organizationId: { toString: () => 'org-id' },
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-02T00:00:00Z'),
  });

  assert.equal(safeUser.id, 'user-id');
  assert.equal(safeUser.organizationId, 'org-id');
  assert.equal(Object.hasOwn(safeUser, 'password'), false);
  assert.equal(Object.hasOwn(safeUser, 'passwordHash'), false);
});

test('generateToken signs JWT with userId, role, and organizationId', () => {
  process.env.JWT_SECRET = 'test-secret';
  process.env.JWT_EXPIRES_IN = '1h';

  const token = generateToken({
    _id: { toString: () => 'user-id' },
    role: 'owner',
    organizationId: { toString: () => 'org-id' },
  });
  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  assert.equal(decoded.userId, 'user-id');
  assert.equal(decoded.role, 'owner');
  assert.equal(decoded.organizationId, 'org-id');
});

test('protect attaches identity when a valid bearer token is provided', async () => {
  process.env.JWT_SECRET = 'test-secret';
  const token = jwt.sign(
    { userId: 'user-id', role: 'owner', organizationId: 'org-id' },
    process.env.JWT_SECRET,
    { expiresIn: '1h' },
  );
  const req = { get: () => `Bearer ${token}` };
  const res = createMockResponse();
  let nextCalled = false;

  protect(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.deepEqual(req.user, { userId: 'user-id', role: 'owner', organizationId: 'org-id' });
});

test('protect rejects missing, invalid, and expired bearer tokens with 401', async () => {
  process.env.JWT_SECRET = 'test-secret';

  for (const authorization of [
    '',
    'Bearer not-a-real-token',
    `Bearer ${jwt.sign({ userId: 'user-id', role: 'owner', organizationId: 'org-id' }, process.env.JWT_SECRET, { expiresIn: '-1s' })}`,
  ]) {
    const req = { get: () => authorization };
    const res = createMockResponse();
    let nextCalled = false;

    protect(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.success, false);
  }
});


test('User role model explicitly supports owner, reviewer, and member', () => {
  assert.deepEqual(USER_ROLE_VALUES, ['owner', 'reviewer', 'member']);

  const organizationId = new mongoose.Types.ObjectId();
  for (const role of USER_ROLE_VALUES) {
    const user = new User({
      name: `${role} user`,
      email: `${role}@example.com`,
      password: 'hashed-password',
      role,
      organizationId,
    });

    const validationError = user.validateSync();
    assert.equal(validationError, undefined);
  }
});

test('User role model rejects invalid roles', () => {
  const user = new User({
    name: 'Invalid Role User',
    email: 'invalid@example.com',
    password: 'hashed-password',
    role: 'admin',
    organizationId: new mongoose.Types.ObjectId(),
  });

  const validationError = user.validateSync();
  assert.ok(validationError);
  assert.ok(validationError.errors.role);
});

test('User role defaults securely to member when role is omitted', () => {
  const user = new User({
    name: 'Default Role User',
    email: 'default@example.com',
    password: 'hashed-password',
    organizationId: new mongoose.Types.ObjectId(),
  });

  assert.equal(user.role, USER_ROLES.MEMBER);
});

test('registration ignores arbitrary role payloads and creates only a new organization owner', () => {
  const requestedBody = {
    name: 'Attacker',
    email: 'attacker@example.com',
    password: 'secret123',
    organizationName: 'New Safe Org',
    organizationId: new mongoose.Types.ObjectId().toString(),
    role: USER_ROLES.MEMBER,
  };
  const serverOrganizationId = new mongoose.Types.ObjectId();

  const allowedRegistrationFields = buildNewOrganizationOwnerInput(
    { name: requestedBody.name, email: normalizeEmail(requestedBody.email) },
    serverOrganizationId,
    'hashed-password',
  );

  assert.equal(Object.hasOwn(allowedRegistrationFields, 'organizationName'), false);
  assert.notEqual(allowedRegistrationFields.organizationId.toString(), requestedBody.organizationId);
  assert.equal(allowedRegistrationFields.organizationId, serverOrganizationId);
  assert.equal(allowedRegistrationFields.role, USER_ROLES.OWNER);
});


test('requireRole allows owner and reviewer roles from authenticated identity', () => {
  for (const role of [USER_ROLES.OWNER, USER_ROLES.REVIEWER]) {
    const req = {
      user: { userId: 'user-id', role, organizationId: 'org-id' },
      body: { role: USER_ROLES.MEMBER },
    };
    const res = createMockResponse();
    let nextCalled = false;

    requireRole([USER_ROLES.OWNER, USER_ROLES.REVIEWER])(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, true);
    assert.equal(res.statusCode, 200);
  }
});

test('requireRole denies member role with 403 and ignores request body role', () => {
  const req = {
    user: { userId: 'user-id', role: USER_ROLES.MEMBER, organizationId: 'org-id' },
    body: { role: USER_ROLES.OWNER },
  };
  const res = createMockResponse();
  let nextCalled = false;

  requireRole([USER_ROLES.OWNER, USER_ROLES.REVIEWER])(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.success, false);
});

test('requireRole denies unauthenticated requests with 401 when protect has not attached req.user', () => {
  const req = { body: { role: USER_ROLES.OWNER } };
  const res = createMockResponse();
  let nextCalled = false;

  requireRole([USER_ROLES.OWNER])(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 401);
  assert.equal(res.body.success, false);
});

test('requireRole handles invalid role configuration safely', () => {
  for (const invalidConfig of [[], ['admin'], [USER_ROLES.OWNER, 'admin'], null]) {
    const req = { user: { userId: 'user-id', role: USER_ROLES.OWNER, organizationId: 'org-id' } };
    const res = createMockResponse();
    let nextError;
    let nextCalled = false;

    requireRole(invalidConfig)(req, res, (error) => {
      nextCalled = true;
      nextError = error;
    });

    assert.equal(nextCalled, true);
    assert.equal(nextError.statusCode, 500);
    assert.match(nextError.message, /Invalid role authorization configuration/);
    assert.equal(res.statusCode, 200);
  }
});


test('organization isolation allows same-organization resources', async () => {
  const { requireSameOrganization } = await import('../middleware/organizationScope.js');
  const req = {
    user: { userId: 'user-id', role: USER_ROLES.MEMBER, organizationId: 'org-a' },
    body: { organizationId: 'org-b' },
  };
  const res = createMockResponse();
  let nextCalled = false;

  await requireSameOrganization(() => ({ id: 'resource-id', organizationId: 'org-a' }))(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.equal(req.organizationId, 'org-a');
  assert.equal(req.resource.id, 'resource-id');
  assert.equal(res.statusCode, 200);
});

test('organization isolation forbids different-organization resources with 403', async () => {
  const { requireSameOrganization } = await import('../middleware/organizationScope.js');
  const req = { user: { userId: 'user-id', role: USER_ROLES.MEMBER, organizationId: 'org-a' } };
  const res = createMockResponse();
  let nextCalled = false;

  await requireSameOrganization(() => ({ id: 'resource-id', organizationId: 'org-b' }))(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.success, false);
});

test('organization isolation rejects missing authenticated organization identity safely', async () => {
  const { requireSameOrganization } = await import('../middleware/organizationScope.js');
  const req = { user: { userId: 'user-id', role: USER_ROLES.MEMBER } };
  const res = createMockResponse();
  let nextCalled = false;

  await requireSameOrganization(() => ({ id: 'resource-id', organizationId: 'org-a' }))(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 401);
  assert.equal(res.body.success, false);
});

test('organization isolation cannot be bypassed by client-supplied organizationId', async () => {
  const { requireSameOrganization, scopeToAuthenticatedOrganization } = await import('../middleware/organizationScope.js');
  const req = {
    user: { userId: 'user-id', role: USER_ROLES.MEMBER, organizationId: 'org-a' },
    params: { organizationId: 'org-b' },
    query: { organizationId: 'org-b' },
    body: { organizationId: 'org-b' },
    headers: { 'x-organization-id': 'org-b' },
  };
  const res = createMockResponse();
  let nextCalled = false;

  await requireSameOrganization(() => ({ id: 'resource-id', organizationId: req.body.organizationId }))(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
  assert.deepEqual(scopeToAuthenticatedOrganization(req, { status: 'active' }), {
    status: 'active',
    organizationId: 'org-a',
  });
});


test('user routes list only authenticated organization users for owners and reviewers', async () => {
  const { listUsers } = await import('../controllers/userController.js');
  const orgId = new mongoose.Types.ObjectId();

  const originalFind = User.find;
  User.find = (filter) => {
    assert.deepEqual(filter, { organizationId: orgId.toString() });
    return {
      sort(sortSpec) {
        assert.deepEqual(sortSpec, { createdAt: -1 });
        return Promise.resolve([
          new User({ name: 'Owner', email: 'owner@example.com', password: 'hash', role: USER_ROLES.OWNER, organizationId: orgId }),
        ]);
      },
    };
  };

  try {
    for (const role of [USER_ROLES.OWNER, USER_ROLES.REVIEWER]) {
      const req = { user: { userId: 'auth-user', role, organizationId: orgId.toString() } };
      const res = createMockResponse();

      await listUsers(req, res, assert.fail);

      assert.equal(res.statusCode, 200);
      assert.equal(res.body.success, true);
      assert.equal(res.body.users.length, 1);
      assert.equal(Object.hasOwn(res.body.users[0], 'password'), false);
      assert.equal(Object.hasOwn(res.body.users[0], 'passwordHash'), false);
    }
  } finally {
    User.find = originalFind;
  }
});

test('user route role chain denies members with 403', () => {
  const req = { user: { userId: 'member-id', role: USER_ROLES.MEMBER, organizationId: 'org-id' } };
  const res = createMockResponse();
  let nextCalled = false;

  requireRole([USER_ROLES.OWNER, USER_ROLES.REVIEWER])(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
});

test('user lookup returns same organization user and filters sensitive fields', async () => {
  const { getUserById } = await import('../controllers/userController.js');
  const orgId = new mongoose.Types.ObjectId();
  const userId = new mongoose.Types.ObjectId();
  const user = new User({ _id: userId, name: 'Reviewer', email: 'reviewer@example.com', password: 'hash', role: USER_ROLES.REVIEWER, organizationId: orgId });
  const originalFindById = User.findById;
  User.findById = async (id) => {
    assert.equal(id, userId.toString());
    return user;
  };

  try {
    const req = { params: { id: userId.toString() }, user: { userId: 'owner-id', role: USER_ROLES.OWNER, organizationId: orgId.toString() } };
    const res = createMockResponse();

    await getUserById(req, res, assert.fail);

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.success, true);
    assert.equal(res.body.user.id, userId.toString());
    assert.equal(Object.hasOwn(res.body.user, 'password'), false);
    assert.equal(Object.hasOwn(res.body.user, 'passwordHash'), false);
    assert.equal(Object.hasOwn(res.body.user, 'jwtSecret'), false);
  } finally {
    User.findById = originalFindById;
  }
});

test('user lookup forbids cross-organization access with 403', async () => {
  const { getUserById } = await import('../controllers/userController.js');
  const requestedUserId = new mongoose.Types.ObjectId();
  const otherOrgId = new mongoose.Types.ObjectId();
  const originalFindById = User.findById;
  User.findById = async () => new User({ _id: requestedUserId, name: 'Other', email: 'other@example.com', password: 'hash', role: USER_ROLES.MEMBER, organizationId: otherOrgId });

  try {
    const req = { params: { id: requestedUserId.toString() }, user: { userId: 'owner-id', role: USER_ROLES.OWNER, organizationId: new mongoose.Types.ObjectId().toString() } };
    const res = createMockResponse();

    await getUserById(req, res, assert.fail);

    assert.equal(res.statusCode, 403);
    assert.equal(res.body.success, false);
  } finally {
    User.findById = originalFindById;
  }
});

test('user lookup rejects invalid IDs and reports nonexistent users', async () => {
  const { getUserById } = await import('../controllers/userController.js');
  const reqWithInvalidId = { params: { id: 'not-an-object-id' }, user: { organizationId: 'org-id' } };
  const invalidRes = createMockResponse();

  await getUserById(reqWithInvalidId, invalidRes, assert.fail);
  assert.equal(invalidRes.statusCode, 400);

  const validMissingId = new mongoose.Types.ObjectId().toString();
  const originalFindById = User.findById;
  User.findById = async () => null;

  try {
    const missingRes = createMockResponse();
    await getUserById({ params: { id: validMissingId }, user: { organizationId: 'org-id' } }, missingRes, assert.fail);
    assert.equal(missingRes.statusCode, 404);
    assert.equal(missingRes.body.success, false);
  } finally {
    User.findById = originalFindById;
  }
});


test('document listing lets owners see all organization documents', async () => {
  const { listDocuments } = await import('../controllers/documentController.js');
  const Document = (await import('../models/Document.js')).default;
  const orgId = new mongoose.Types.ObjectId();
  const originalFind = Document.find;
  Document.find = (filter) => {
    assert.deepEqual(filter, { organizationId: orgId.toString() });
    return { sort: () => Promise.resolve([]) };
  };
  try {
    const res = createMockResponse();
    await listDocuments({ user: { userId: 'owner-id', role: USER_ROLES.OWNER, organizationId: orgId.toString() } }, res, assert.fail);
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body.documents, []);
  } finally {
    Document.find = originalFind;
  }
});

test('reviewer upload uses authenticated organization and uploadedBy identity', async () => {
  const { createDocument } = await import('../controllers/documentController.js');
  const Document = (await import('../models/Document.js')).default;
  const orgId = new mongoose.Types.ObjectId().toString();
  const userId = new mongoose.Types.ObjectId().toString();
  const originalCreate = Document.create;
  Document.create = async (input) => {
    assert.equal(input.organizationId, orgId);
    assert.equal(input.uploadedBy, userId);
    assert.equal(input.file.originalName, 'nda.pdf');
    assert.ok(!Object.hasOwn(input, 'clientPath'));
    return { _id: new mongoose.Types.ObjectId(), ...input, createdAt: new Date(), updatedAt: new Date(), status: 'uploaded' };
  };
  try {
    const req = {
      user: { userId, role: USER_ROLES.REVIEWER, organizationId: orgId },
      body: { name: 'NDA', organizationId: new mongoose.Types.ObjectId().toString() },
      file: { originalname: 'nda.pdf', mimetype: 'application/pdf', size: 1024, buffer: Buffer.from('pdf') },
    };
    const res = createMockResponse();
    await createDocument(req, res, assert.fail);
    assert.equal(res.statusCode, 201);
    assert.equal(res.body.document.organizationId, orgId);
    assert.equal(res.body.document.uploadedBy, userId);
  } finally {
    Document.create = originalCreate;
  }
});

test('reviewers list only their own uploaded documents', async () => {
  const { listDocuments } = await import('../controllers/documentController.js');
  const Document = (await import('../models/Document.js')).default;
  const orgId = 'org-a';
  const userId = 'reviewer-id';
  const originalFind = Document.find;
  Document.find = (filter) => {
    assert.deepEqual(filter, { uploadedBy: userId, organizationId: orgId });
    return { sort: () => Promise.resolve([]) };
  };
  try {
    const res = createMockResponse();
    await listDocuments({ user: { userId, role: USER_ROLES.REVIEWER, organizationId: orgId } }, res, assert.fail);
    assert.equal(res.statusCode, 200);
  } finally {
    Document.find = originalFind;
  }
});

test('document retrieval denies cross-organization access with 403', async () => {
  const { getDocumentById } = await import('../controllers/documentController.js');
  const Document = (await import('../models/Document.js')).default;
  const documentId = new mongoose.Types.ObjectId();
  const originalFindById = Document.findById;
  Document.findById = async () => ({ _id: documentId, organizationId: 'org-b', uploadedBy: 'u1', file: {}, name: 'Doc' });
  try {
    const res = createMockResponse();
    await getDocumentById({ params: { id: documentId.toString() }, user: { userId: 'u1', role: USER_ROLES.OWNER, organizationId: 'org-a' } }, res, assert.fail);
    assert.equal(res.statusCode, 403);
  } finally {
    Document.findById = originalFindById;
  }
});

test('member document listing is denied', async () => {
  const { listDocuments } = await import('../controllers/documentController.js');
  const res = createMockResponse();
  await listDocuments({ user: { userId: 'member-id', role: USER_ROLES.MEMBER, organizationId: 'org-id' } }, res, assert.fail);
  assert.equal(res.statusCode, 403);
});

test('valid document retrieval returns metadata without filesystem path', async () => {
  const { getDocumentById } = await import('../controllers/documentController.js');
  const Document = (await import('../models/Document.js')).default;
  const orgId = 'org-a';
  const userId = 'u1';
  const documentId = new mongoose.Types.ObjectId();
  const originalFindById = Document.findById;
  Document.findById = async () => ({
    _id: documentId,
    organizationId: orgId,
    uploadedBy: userId,
    name: 'Doc',
    status: 'uploaded',
    file: { storageKey: 'documents/u1/key.pdf', originalName: 'doc.pdf', mimeType: 'application/pdf', size: 5 },
  });
  try {
    const res = createMockResponse();
    await getDocumentById({ params: { id: documentId.toString() }, user: { userId, role: USER_ROLES.REVIEWER, organizationId: orgId } }, res, assert.fail);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.document.file.storageKey, 'documents/u1/key.pdf');
    assert.equal(Object.hasOwn(res.body.document.file, 'path'), false);
  } finally {
    Document.findById = originalFindById;
  }
});

test('document retrieval rejects invalid IDs', async () => {
  const { getDocumentById } = await import('../controllers/documentController.js');
  const res = createMockResponse();
  await getDocumentById({ params: { id: 'not-valid' }, user: { organizationId: 'org-a' } }, res, assert.fail);
  assert.equal(res.statusCode, 400);
});

test('document upload validates file presence, type, and size', async () => {
  const { createDocument, MAX_DOCUMENT_BYTES } = await import('../controllers/documentController.js');
  for (const file of [null, { originalname: 'x.exe', mimetype: 'application/x-msdownload', size: 1 }, { originalname: 'huge.pdf', mimetype: 'application/pdf', size: MAX_DOCUMENT_BYTES + 1 }]) {
    const res = createMockResponse();
    await createDocument({ user: { userId: 'u1', organizationId: 'org-a' }, body: {}, file }, res, assert.fail);
    assert.equal(res.statusCode, 400);
  }
});
