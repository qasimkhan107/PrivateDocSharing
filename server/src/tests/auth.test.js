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
