import { Router } from 'express';
import {
  joinCollaboration,
  leaveCollaboration,
  getCollaborationStatus,
  updateCursor,
  shareWorkspace
} from '../controllers/collaborationController';

const router = Router();

// Join collaboration session for workspace
router.post('/:workspaceId/join', joinCollaboration);

// Leave collaboration session
router.post('/:workspaceId/leave', leaveCollaboration);

// Get collaboration status
router.get('/:workspaceId/status', getCollaborationStatus);

// Update cursor position
router.put('/:workspaceId/cursor', updateCursor);

// Share workspace
router.post('/:workspaceId/share', shareWorkspace);

export default router;
