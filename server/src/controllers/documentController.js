import crypto from 'node:crypto';
import mongoose from 'mongoose';
import Document from '../models/Document.js';
import { USER_ROLES } from '../models/User.js';
import { assertSameOrganization, scopeToAuthenticatedOrganization } from '../middleware/organizationScope.js';

export const ALLOWED_DOCUMENT_MIME_TYPES = Object.freeze([
  'application/pdf',
  'text/plain',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
]);
export const MAX_DOCUMENT_BYTES = 10 * 1024 * 1024;

function serializeDocument(document) {
  return {
    id: document._id?.toString?.() ?? document.id,
    organizationId: document.organizationId?.toString?.(),
    name: document.name,
    file: {
      originalName: document.file.originalName,
      mimeType: document.file.mimeType,
      size: document.file.size,
      storageKey: document.file.storageKey,
    },
    uploadedBy: document.uploadedBy?.toString?.(),
    status: document.status,
    createdAt: document.createdAt,
    updatedAt: document.updatedAt,
  };
}

function validateUploadedFile(file) {
  if (!file) return 'Document file is required';
  if (!ALLOWED_DOCUMENT_MIME_TYPES.includes(file.mimetype)) return 'Unsupported document type';
  if (file.size > MAX_DOCUMENT_BYTES) return 'Document exceeds 10 MB';
  return null;
}

function getSafeStorageKey(userId, file) {
  const extension = file.originalname?.includes('.') ? file.originalname.split('.').pop().toLowerCase() : 'bin';
  return `documents/${userId}/${crypto.randomUUID()}.${extension}`;
}

export async function createDocument(req, res, next) {
  try {
    const validationMessage = validateUploadedFile(req.file);
    if (validationMessage) return res.status(400).json({ success: false, message: validationMessage });

    const document = await Document.create({
      organizationId: req.user.organizationId,
      name: (req.body?.name || req.file.originalname).trim(),
      file: {
        storageKey: getSafeStorageKey(req.user.userId, req.file),
        originalName: req.file.originalname,
        mimeType: req.file.mimetype,
        size: req.file.size,
      },
      uploadedBy: req.user.userId,
    });

    return res.status(201).json({ success: true, document: serializeDocument(document) });
  } catch (error) {
    return next(error);
  }
}

export async function listDocuments(req, res, next) {
  try {
    if (req.user.role === USER_ROLES.MEMBER) {
      return res.status(403).json({ success: false, message: 'Members cannot list documents' });
    }

    const extraFilter = req.user.role === USER_ROLES.REVIEWER ? { uploadedBy: req.user.userId } : {};
    const documents = await Document.find(scopeToAuthenticatedOrganization(req, extraFilter)).sort({ createdAt: -1 });

    return res.json({ success: true, documents: documents.map(serializeDocument) });
  } catch (error) {
    return next(error);
  }
}

export async function getDocumentById(req, res, next) {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid document ID' });
    }

    const document = await Document.findById(id);
    if (!document) return res.status(404).json({ success: false, message: 'Document not found' });

    const organizationCheck = assertSameOrganization(req, document);
    if (!organizationCheck.allowed) {
      return res.status(organizationCheck.statusCode).json({ success: false, message: organizationCheck.message });
    }

    if (req.user.role === USER_ROLES.MEMBER) {
      return res.status(403).json({ success: false, message: 'Members cannot retrieve documents directly' });
    }
    if (req.user.role === USER_ROLES.REVIEWER && document.uploadedBy.toString() !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Reviewers can only access their own uploads' });
    }

    return res.json({ success: true, document: serializeDocument(document) });
  } catch (error) {
    return next(error);
  }
}
