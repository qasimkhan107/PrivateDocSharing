import mongoose from 'mongoose';

export const DOCUMENT_STATUS = Object.freeze({
  UPLOADED: 'uploaded',
});

const documentSchema = new mongoose.Schema(
  {
    organizationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Organization',
      required: true,
      index: true,
    },
    name: {
      type: String,
      required: [true, 'Document name is required'],
      trim: true,
      maxlength: [255, 'Document name cannot exceed 255 characters'],
    },
    file: {
      storageKey: { type: String, required: true },
      originalName: { type: String, required: true },
      mimeType: { type: String, required: true },
      size: { type: Number, required: true },
    },
    uploadedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    status: {
      type: String,
      enum: Object.values(DOCUMENT_STATUS),
      default: DOCUMENT_STATUS.UPLOADED,
      required: true,
    },
  },
  { timestamps: true },
);

documentSchema.index({ organizationId: 1, createdAt: -1 });
documentSchema.index({ organizationId: 1, uploadedBy: 1, createdAt: -1 });

const Document = mongoose.model('Document', documentSchema);

export default Document;
