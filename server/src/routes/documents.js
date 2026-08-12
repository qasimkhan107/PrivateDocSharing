import express from 'express';
import multer from 'multer';
import { createDocument, getDocumentById, listDocuments, MAX_DOCUMENT_BYTES } from '../controllers/documentController.js';
import { protect } from '../middleware/auth.js';
import { requireOrganizationIdentity } from '../middleware/organizationScope.js';

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_DOCUMENT_BYTES },
});

router.use(protect, requireOrganizationIdentity);

router.post('/', upload.single('file'), createDocument);
router.get('/', listDocuments);
router.get('/:id', getDocumentById);

export default router;
