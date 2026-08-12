import express from 'express';
import mongoose from 'mongoose';
import Document from '../models/Document.js';
import DocumentRequest, { REQUEST_STATUSES } from '../models/DocumentRequest.js';
import User from '../models/User.js';
import { requireAuth } from '../middleware/auth.js';
import { canTransition } from '../services/requestStatus.js';

const router = express.Router();

function httpError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}

function assertObjectId(id, name) {
  if (!mongoose.isValidObjectId(id)) throw httpError(400, `${name} is invalid`);
}

function scopedQuery(req, extra = {}) {
  const query = { organizationId: req.user.organizationId, ...extra };
  if (req.user.role === 'MEMBER') query.recipientId = req.user.userId;
  return query;
}

router.use(requireAuth);

router.post('/', async (req, res, next) => {
  try {
    const { documentId, recipientId, message, requiresSignature } = req.body;
    assertObjectId(documentId, 'documentId');
    assertObjectId(recipientId, 'recipientId');

    const [document, recipient] = await Promise.all([
      Document.findOne({ _id: documentId, organizationId: req.user.organizationId }),
      User.findOne({ _id: recipientId, organizationId: req.user.organizationId }),
    ]);

    if (!document) throw httpError(404, 'Document not found in your organization');
    if (!recipient) throw httpError(404, 'Recipient not found in your organization');

    const request = await DocumentRequest.create({
      organizationId: req.user.organizationId,
      documentId,
      senderId: req.user.userId,
      recipientId,
      message: message || '',
      requiresSignature: Boolean(requiresSignature),
      status: 'SENT',
    });

    res.status(201).json({ success: true, data: request });
  } catch (err) {
    next(err);
  }
});

router.get('/', async (req, res, next) => {
  try {
    const requests = await DocumentRequest.find(scopedQuery(req)).sort({ createdAt: -1 });
    res.json({ success: true, data: requests });
  } catch (err) {
    next(err);
  }
});

router.get('/:id', async (req, res, next) => {
  try {
    assertObjectId(req.params.id, 'requestId');
    const request = await DocumentRequest.findOne(scopedQuery(req, { _id: req.params.id }));
    if (!request) throw httpError(404, 'Request not found');
    res.json({ success: true, data: request });
  } catch (err) {
    next(err);
  }
});

router.patch('/:id/status', async (req, res, next) => {
  try {
    assertObjectId(req.params.id, 'requestId');
    const nextStatus = String(req.body.status || '').toUpperCase();
    if (!REQUEST_STATUSES.includes(nextStatus)) throw httpError(400, 'Invalid status');

    const request = await DocumentRequest.findOne(scopedQuery(req, { _id: req.params.id }));
    if (!request) throw httpError(404, 'Request not found');
    if (!canTransition(request.status, nextStatus, req.user, request)) {
      throw httpError(403, 'Status transition is not allowed');
    }

    request.status = nextStatus;
    await request.save();
    res.json({ success: true, data: request });
  } catch (err) {
    next(err);
  }
});

export default router;
