import { Request, Response } from 'express';
import Docker from 'dockerode';
import os from 'os';
import { v4 as uuidv4 } from 'uuid';
import { SystemMetrics, User, AuditLog } from '../types';
import { config } from '../config';
import { logger } from '../utils/logger';
import { auditLogger } from '../utils/auditLogger';
import { AuthenticatedRequest } from '../auth/middleware';

const docker = new Docker({ socketPath: config.docker.socketPath });

// In-memory storage for demo - replace with database in production
const users: User[] = [];

export const getSystemMetrics = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const cpus = os.cpus();
    const totalMemory = os.totalmem();
    const freeMemory = os.freemem();
    const usedMemory = totalMemory - freeMemory;

    // Get Docker container stats
    const containers = await docker.listContainers({ all: true });
    const runningContainers = containers.filter(c => c.State === 'running');

    const metrics: SystemMetrics = {
      cpu: {
        usage: await getCpuUsage(),
        cores: cpus.length
      },
      memory: {
        used: usedMemory,
        total: totalMemory,
        free: freeMemory
      },
      disk: await getDiskUsage(),
      network: await getNetworkStats(),
      containers: {
        running: runningContainers.length,
        stopped: containers.length - runningContainers.length,
        total: containers.length
      },
      timestamp: new Date()
    };

    res.json({
      success: true,
      data: metrics
    });
  } catch (error: any) {
    logger.error('Failed to get system metrics', { error: error.message });
    res.status(500).json({
      success: false,
      error: 'Failed to get system metrics'
    });
  }
};

export const getSystemStats = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const stats = {
      totalUsers: users.length,
      activeUsers: users.filter(u => u.isActive).length,
      bannedUsers: users.filter(u => u.isBanned).length,
      totalWorkspaces: 0, // Would come from database
      activeWorkspaces: 0, // Would come from database
      uptime: process.uptime(),
      nodeVersion: process.version,
      platform: os.platform(),
      arch: os.arch(),
      loadAverage: os.loadavg(),
      timestamp: new Date()
    };

    res.json({
      success: true,
      data: stats
    });
  } catch (error: any) {
    logger.error('Failed to get system stats', { error: error.message });
    res.status(500).json({
      success: false,
      error: 'Failed to get system stats'
    });
  }
};

export const getUsers = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { page = 1, limit = 20, search, role, status } = req.query;
    
    let filteredUsers = [...users];

    // Apply filters
    if (search) {
      const searchTerm = search.toString().toLowerCase();
      filteredUsers = filteredUsers.filter(u => 
        u.username.toLowerCase().includes(searchTerm) ||
        u.email.toLowerCase().includes(searchTerm)
      );
    }

    if (role) {
      filteredUsers = filteredUsers.filter(u => u.role === role);
    }

    if (status === 'active') {
      filteredUsers = filteredUsers.filter(u => u.isActive && !u.isBanned);
    } else if (status === 'inactive') {
      filteredUsers = filteredUsers.filter(u => !u.isActive);
    } else if (status === 'banned') {
      filteredUsers = filteredUsers.filter(u => u.isBanned);
    }

    // Pagination
    const startIndex = (Number(page) - 1) * Number(limit);
    const endIndex = startIndex + Number(limit);
    const paginatedUsers = filteredUsers.slice(startIndex, endIndex);

    // Remove sensitive information
    const safeUsers = paginatedUsers.map(u => {
      const { password, passwordHash, twoFactorSecret, ...safeUser } = u;
      return safeUser;
    });

    res.json({
      success: true,
      data: {
        users: safeUsers,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total: filteredUsers.length,
          pages: Math.ceil(filteredUsers.length / Number(limit))
        }
      }
    });
  } catch (error: any) {
    logger.error('Failed to get users', { error: error.message });
    res.status(500).json({
      success: false,
      error: 'Failed to get users'
    });
  }
};

export const updateUser = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    const userIndex = users.findIndex(u => u.id === id);
    if (userIndex === -1) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Prevent updating sensitive fields
    const allowedUpdates = ['role', 'isActive', 'isBanned', 'emailVerified'];
    const filteredUpdates = Object.keys(updates)
      .filter(key => allowedUpdates.includes(key))
      .reduce((obj: any, key) => {
        obj[key] = updates[key];
        return obj;
      }, {});

    users[userIndex] = {
      ...users[userIndex],
      ...filteredUpdates,
      updatedAt: new Date()
    };

    auditLogger.log({
      id: uuidv4(),
      userId: req.user!.id,
      action: 'USER_UPDATED',
      resource: 'user',
      resourceId: id,
      details: filteredUpdates,
      ip: req.ip,
      userAgent: req.get('User-Agent') || '',
      timestamp: new Date()
    });

    const { password, passwordHash, twoFactorSecret, ...safeUser } = users[userIndex];

    res.json({
      success: true,
      data: safeUser
    });
  } catch (error: any) {
    logger.error('Failed to update user', { error: error.message, userId: req.params.id });
    res.status(500).json({
      success: false,
      error: 'Failed to update user'
    });
  }
};

export const deleteUser = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;

    const userIndex = users.findIndex(u => u.id === id);
    if (userIndex === -1) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Don't actually delete, just deactivate
    users[userIndex].isActive = false;
    users[userIndex].updatedAt = new Date();

    auditLogger.log({
      id: uuidv4(),
      userId: req.user!.id,
      action: 'USER_DELETED',
      resource: 'user',
      resourceId: id,
      details: { username: users[userIndex].username },
      ip: req.ip,
      userAgent: req.get('User-Agent') || '',
      timestamp: new Date()
    });

    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error: any) {
    logger.error('Failed to delete user', { error: error.message, userId: req.params.id });
    res.status(500).json({
      success: false,
      error: 'Failed to delete user'
    });
  }
};

export const getAuditLogs = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { 
      page = 1, 
      limit = 50, 
      userId, 
      action, 
      resource,
      startDate,
      endDate 
    } = req.query;

    let logs = auditLogger.getLogs(
      userId?.toString(),
      action?.toString(),
      Number(limit) * Number(page)
    );

    // Additional filtering
    if (resource) {
      logs = logs.filter(log => log.resource === resource);
    }

    if (startDate) {
      const start = new Date(startDate.toString());
      logs = logs.filter(log => log.timestamp >= start);
    }

    if (endDate) {
      const end = new Date(endDate.toString());
      logs = logs.filter(log => log.timestamp <= end);
    }

    // Pagination
    const startIndex = (Number(page) - 1) * Number(limit);
    const endIndex = startIndex + Number(limit);
    const paginatedLogs = logs.slice(startIndex, endIndex);

    res.json({
      success: true,
      data: {
        logs: paginatedLogs,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total: logs.length,
          pages: Math.ceil(logs.length / Number(limit))
        }
      }
    });
  } catch (error: any) {
    logger.error('Failed to get audit logs', { error: error.message });
    res.status(500).json({
      success: false,
      error: 'Failed to get audit logs'
    });
  }
};

export const manageContainers = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { action } = req.query;
    const { id } = req.params;

    if (req.method === 'GET') {
      // List all containers
      const containers = await docker.listContainers({ all: true });
      const containerInfo = await Promise.all(
        containers.map(async (containerInfo) => {
          try {
            const container = docker.getContainer(containerInfo.Id);
            const stats = await container.stats({ stream: false });
            return {
              ...containerInfo,
              stats: {
                cpu: calculateCpuPercent(stats),
                memory: calculateMemoryUsage(stats),
              }
            };
          } catch (error) {
            return {
              ...containerInfo,
              stats: null
            };
          }
        })
      );

      res.json({
        success: true,
        data: containerInfo
      });
    } else if (req.method === 'POST' && action === 'stop') {
      // Stop container
      const container = docker.getContainer(id);
      await container.stop();

      auditLogger.log({
        id: uuidv4(),
        userId: req.user!.id,
        action: 'CONTAINER_STOPPED',
        resource: 'container',
        resourceId: id,
        details: {},
        ip: req.ip,
        userAgent: req.get('User-Agent') || '',
        timestamp: new Date()
      });

      res.json({
        success: true,
        message: 'Container stopped successfully'
      });
    } else if (req.method === 'DELETE') {
      // Remove container
      const container = docker.getContainer(id);
      await container.remove({ force: true });

      auditLogger.log({
        id: uuidv4(),
        userId: req.user!.id,
        action: 'CONTAINER_REMOVED',
        resource: 'container',
        resourceId: id,
        details: {},
        ip: req.ip,
        userAgent: req.get('User-Agent') || '',
        timestamp: new Date()
      });

      res.json({
        success: true,
        message: 'Container removed successfully'
      });
    }
  } catch (error: any) {
    logger.error('Failed to manage container', { 
      error: error.message, 
      containerId: req.params.id,
      action: req.query.action 
    });
    res.status(500).json({
      success: false,
      error: 'Failed to manage container'
    });
  }
};

// Helper functions
async function getCpuUsage(): Promise<number> {
  return new Promise((resolve) => {
    const startUsage = process.cpuUsage();
    setTimeout(() => {
      const currentUsage = process.cpuUsage(startUsage);
      const totalUsage = currentUsage.user + currentUsage.system;
      const percentage = (totalUsage / 1000000) * 100; // Convert to percentage
      resolve(Math.min(percentage, 100));
    }, 100);
  });
}

async function getDiskUsage() {
  // This is a simplified version - in production you'd use a proper disk usage library
  return {
    used: 0,
    total: 0,
    free: 0
  };
}

async function getNetworkStats() {
  // This is a simplified version - in production you'd get actual network stats
  return {
    bytesIn: 0,
    bytesOut: 0
  };
}

function calculateCpuPercent(stats: any): number {
  const cpuDelta = stats.cpu_stats.cpu_usage.total_usage - stats.precpu_stats.cpu_usage.total_usage;
  const systemDelta = stats.cpu_stats.system_cpu_usage - stats.precpu_stats.system_cpu_usage;
  const cpuPercent = (cpuDelta / systemDelta) * stats.cpu_stats.cpu_usage.percpu_usage.length * 100.0;
  return Math.round(cpuPercent * 100) / 100;
}

function calculateMemoryUsage(stats: any): { used: number; limit: number; percent: number } {
  const used = stats.memory_stats.usage;
  const limit = stats.memory_stats.limit;
  const percent = (used / limit) * 100;
  return {
    used,
    limit,
    percent: Math.round(percent * 100) / 100
  };
}
