import { Router } from 'express';
import {
  createWorkspace,
  getWorkspaces,
  getWorkspace,
  startWorkspace,
  stopWorkspace,
  deleteWorkspace
} from '../controllers/workspaceController';
import { requireRole, validateWorkspaceAccess } from '../auth/middleware';

const router = Router();

// Get all workspaces for current user
router.get('/', getWorkspaces);

// Create new workspace
router.post('/', createWorkspace);

// Get specific workspace
router.get('/:id', validateWorkspaceAccess, getWorkspace);

// Start workspace
router.post('/:id/start', validateWorkspaceAccess, startWorkspace);

// Stop workspace
router.post('/:id/stop', validateWorkspaceAccess, stopWorkspace);

// Delete workspace
router.delete('/:id', validateWorkspaceAccess, deleteWorkspace);

export default router;
