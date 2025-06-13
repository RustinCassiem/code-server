import { Router } from 'express';
import CollaborationController from '../controllers/collaborationController';
import { authenticateToken } from '../auth/middleware';

const router = Router();

// All collaboration routes require authentication
router.use(authenticateToken);

// Note: The CollaborationController instance is created in server.ts
// These routes will be bound to the controller methods there
// For now, we'll create placeholder handlers

router.get('/sessions/:workspaceId', (req, res) => {
  // This will be replaced with controller method
  res.json({ message: 'Collaboration session endpoint - to be implemented' });
});

router.get('/active', (req, res) => {
  // This will be replaced with controller method
  res.json({ message: 'Active collaborations endpoint - to be implemented' });
});

router.post('/invite/:workspaceId', (req, res) => {
  // This will be replaced with controller method
  res.json({ message: 'Invite collaborator endpoint - to be implemented' });
});

export default router;
