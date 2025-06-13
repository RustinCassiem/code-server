import { Router } from 'express';
import { 
  createWorkspace,
  getWorkspaces,
  getWorkspace,
  startWorkspace,
  stopWorkspace,
  getSessions,
  deleteWorkspace
} from '../controllers/workspaceController';
import { authenticateToken, requireRole } from '../auth/middleware';

const router = Router();

// All workspace routes require authentication
router.use(authenticateToken);

// Workspace management
router.post('/', createWorkspace);
router.get('/', getWorkspaces);
router.get('/:id', getWorkspace);
router.delete('/:id', deleteWorkspace);

// Session management
router.post('/:id/start', startWorkspace);
router.post('/:id/stop', stopWorkspace);
router.get('/:id/sessions', getSessions);

export default router;
