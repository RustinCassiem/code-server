import { Request, Response } from 'express';
import { exec } from 'child_process';
import { promisify } from 'util';
import { AuthenticatedRequest } from '../auth/middleware';
import { logger } from '../utils/logger';

const execAsync = promisify(exec);

export const getSystemStats = async (req: AuthenticatedRequest, res: Response) => {
  try {
    // Get system information
    const [cpuInfo, memInfo, diskInfo, dockerInfo] = await Promise.all([
      execAsync('top -bn1 | grep "Cpu(s)" | sed "s/.*, *\\([0-9.]*\\)%* id.*/\\1/" | awk \'{print 100 - $1}\''),
      execAsync('free -m | awk \'NR==2{printf "%.2f", $3*100/$2 }\''),
      execAsync('df -h | awk \'$NF=="/"{printf "%s", $5}\''),
      execAsync('docker ps --format "table {{.Names}}\\t{{.Status}}\\t{{.Ports}}" | tail -n +2').catch(() => ({ stdout: '' }))
    ]);

    const stats = {
      cpu: parseFloat(cpuInfo.stdout.trim()) || 0,
      memory: parseFloat(memInfo.stdout.trim()) || 0,
      disk: diskInfo.stdout.trim(),
      uptime: process.uptime(),
      containers: dockerInfo.stdout.trim().split('\n').filter(line => line.length > 0),
      timestamp: new Date().toISOString()
    };

    res.json(stats);
  } catch (error) {
    logger.error('Error getting system stats:', error);
    res.status(500).json({ error: 'Failed to get system statistics' });
  }
};

export const getAllUsers = async (req: AuthenticatedRequest, res: Response) => {
  try {
    // TODO: Replace with actual database query
    const users = [
      {
        id: '1',
        username: 'admin',
        email: 'admin@example.com',
        role: 'admin',
        isActive: true,
        createdAt: new Date(),
        lastLogin: new Date()
      }
    ];

    res.json(users);
  } catch (error) {
    logger.error('Error getting users:', error);
    res.status(500).json({ error: 'Failed to get users' });
  }
};

export const updateUser = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    // TODO: Implement user update logic with database
    
    logger.info(`Admin ${req.user!.username} updated user ${id}`);
    res.json({ message: 'User updated successfully' });
  } catch (error) {
    logger.error('Error updating user:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
};

export const deleteUser = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;

    if (id === req.user!.id) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }

    // TODO: Implement user deletion logic with database
    
    logger.info(`Admin ${req.user!.username} deleted user ${id}`);
    res.status(204).send();
  } catch (error) {
    logger.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
};

export const getAuditLogs = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { page = 1, limit = 50, filter } = req.query;
    
    // TODO: Implement audit log retrieval from database/files
    const logs = [
      {
        timestamp: new Date(),
        userId: req.user!.id,
        action: 'LOGIN',
        resource: '/auth/login',
        ip: '127.0.0.1',
        userAgent: 'Mozilla/5.0...'
      }
    ];

    res.json({
      logs,
      totalCount: logs.length,
      page: Number(page),
      limit: Number(limit)
    });
  } catch (error) {
    logger.error('Error getting audit logs:', error);
    res.status(500).json({ error: 'Failed to get audit logs' });
  }
};

export const getAllWorkspaces = async (req: AuthenticatedRequest, res: Response) => {
  try {
    // TODO: Get all workspaces from database
    const workspaces = [];

    res.json(workspaces);
  } catch (error) {
    logger.error('Error getting all workspaces:', error);
    res.status(500).json({ error: 'Failed to get workspaces' });
  }
};

export const forceStopWorkspace = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    
    const containerName = `workspace-${id}`;
    await execAsync(`docker stop ${containerName}`);
    
    logger.info(`Admin ${req.user!.username} force stopped workspace ${id}`);
    res.json({ message: 'Workspace stopped successfully' });
  } catch (error) {
    logger.error('Error force stopping workspace:', error);
    res.status(500).json({ error: 'Failed to stop workspace' });
  }
};

export const getSystemLogs = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { lines = 100 } = req.query;
    
    const { stdout } = await execAsync(`tail -n ${lines} logs/combined.log`);
    
    res.json({
      logs: stdout.split('\n').filter(line => line.length > 0),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Error getting system logs:', error);
    res.status(500).json({ error: 'Failed to get system logs' });
  }
};

export const updateSystemSettings = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const settings = req.body;
    
    // TODO: Implement system settings update logic
    
    logger.info(`Admin ${req.user!.username} updated system settings`);
    res.json({ message: 'Settings updated successfully' });
  } catch (error) {
    logger.error('Error updating settings:', error);
    res.status(500).json({ error: 'Failed to update settings' });
  }
};
