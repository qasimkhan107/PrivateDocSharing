import test from 'node:test';
import assert from 'node:assert/strict';
import { canTransition } from './requestStatus.js';

const request = { senderId: 'sender', recipientId: 'recipient' };

test('enforces linear request status flow', () => {
  const actor = { userId: 'recipient', role: 'MEMBER' };
  assert.equal(canTransition('SENT', 'IN_REVIEW', actor, request), true);
  assert.equal(canTransition('SENT', 'SIGNED', actor, request), false);
});

test('only recipient may sign', () => {
  assert.equal(canTransition('DISCUSSION', 'SIGNED', { userId: 'recipient', role: 'MEMBER' }, request), true);
  assert.equal(canTransition('DISCUSSION', 'SIGNED', { userId: 'sender', role: 'MEMBER' }, request), false);
});

test('only sender or privileged user may complete or cancel', () => {
  assert.equal(canTransition('SIGNED', 'COMPLETED', { userId: 'sender', role: 'MEMBER' }, request), true);
  assert.equal(canTransition('SIGNED', 'COMPLETED', { userId: 'recipient', role: 'MEMBER' }, request), false);
  assert.equal(canTransition('SENT', 'CANCELLED', { userId: 'manager', role: 'MANAGER' }, request), true);
});

test('terminal statuses cannot transition', () => {
  assert.equal(canTransition('REJECTED', 'IN_REVIEW', { userId: 'recipient', role: 'MEMBER' }, request), false);
  assert.equal(canTransition('COMPLETED', 'CANCELLED', { userId: 'sender', role: 'MEMBER' }, request), false);
});
