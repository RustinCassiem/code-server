import { Router } from 'express';
import {
  getSystemStats,
  getAllUsers,
  updateUser,
  deleteUser,
  getAuditLogs,
  getAllWorkspaces,
  forceStopWorkspace,
  getSystemLogs,
  updateSystemSettings
} from '../controllers/adminController';
import { requireRole } from '../auth/middleware';

const router = Router();

// All admin routes require admin role
router.use(requireRole(['admin']));

// System monitoring
router.get('/stats', getSystemStats);
router.get('/logs', getSystemLogs);

// User management
router.get('/users', getAllUsers);
router.put('/users/:id', updateUser);
router.delete('/users/:id', deleteUser);

// Audit logs
router.get('/audit', getAuditLogs);

// Workspace management
router.get('/workspaces', getAllWorkspaces);
router.post('/workspaces/:id/stop', forceStopWorkspace);

// System settings
router.put('/settings', updateSystemSettings);

export default router;
