import mongoose from 'mongoose';

export const REQUEST_STATUSES = [
  'SENT',
  'IN_REVIEW',
  'DISCUSSION',
  'SIGNED',
  'COMPLETED',
  'REJECTED',
  'CANCELLED',
];

const documentRequestSchema = new mongoose.Schema(
  {
    organizationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
    documentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Document', required: true, index: true },
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    message: { type: String, trim: true, maxlength: 2000, default: '' },
    requiresSignature: { type: Boolean, default: false },
    status: { type: String, enum: REQUEST_STATUSES, default: 'SENT', index: true },
  },
  { timestamps: true }
);

export default mongoose.models.DocumentRequest || mongoose.model('DocumentRequest', documentRequestSchema);
