import { Router } from 'express';
import { authenticateToken, requireRole } from '../auth/middleware';
import { 
  getSystemMetrics,
  getUsers,
  updateUser,
  deleteUser,
  getAuditLogs,
  getSystemStats,
  manageContainers
} from '../controllers/adminController';

const router = Router();

// All admin routes require authentication and admin role
router.use(authenticateToken);
router.use(requireRole(['admin']));

// System monitoring
router.get('/metrics', getSystemMetrics);
router.get('/stats', getSystemStats);

// User management
router.get('/users', getUsers);
router.put('/users/:id', updateUser);
router.delete('/users/:id', deleteUser);

// Audit logs
router.get('/audit-logs', getAuditLogs);

// Container management
router.get('/containers', manageContainers);
router.post('/containers/:id/stop', manageContainers);
router.delete('/containers/:id', manageContainers);

export default router;
