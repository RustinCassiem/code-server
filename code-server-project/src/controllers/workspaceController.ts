import { Request, Response } from 'express';
import Docker from 'dockerode';
import { v4 as uuidv4 } from 'uuid';
import { Session, Workspace, ContainerResources } from '../types';
import { config } from '../config';
import { logger } from '../utils/logger';
import { auditLogger } from '../utils/auditLogger';
import { AuthenticatedRequest } from '../auth/middleware';

const docker = new Docker({ socketPath: config.docker.socketPath });

// In-memory storage for demo - replace with database in production
const sessions: Session[] = [];
const workspaces: Workspace[] = [];

export const createWorkspace = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const {
      name,
      description,
      template,
      gitUrl,
      branch,
      resources,
      environment,
      extensions,
      settings,
      isPublic
    } = req.body;

    const workspace: Workspace = {
      id: uuidv4(),
      name,
      description,
      userId: req.user!.id,
      gitUrl,
      branch: branch || 'main',
      template,
      templateVersion: '1.0.0',
      resources: resources || {
        cpu: '1',
        memory: '2g',
        storage: '10g',
        networkMode: 'bridge'
      },
      environment: environment || {},
      extensions: extensions || [],
      settings: settings || {
        autoSave: true,
        autoStop: 30,
        maxFileSize: 100,
        allowedExtensions: [],
        blockedExtensions: []
      },
      collaborators: [{
        userId: req.user!.id,
        role: 'owner',
        invitedAt: new Date(),
        acceptedAt: new Date(),
        invitedBy: req.user!.id
      }],
      isPublic: isPublic || false,
      tags: [],
      createdAt: new Date(),
      updatedAt: new Date(),
      status: 'active'
    };

    workspaces.push(workspace);

    auditLogger.log({
      id: uuidv4(),
      userId: req.user!.id,
      action: 'WORKSPACE_CREATED',
      resource: 'workspace',
      resourceId: workspace.id,
      details: { name, template },
      ip: req.ip,
      userAgent: req.get('User-Agent') || '',
      timestamp: new Date()
    });

    logger.info('Workspace created', { workspaceId: workspace.id, userId: req.user!.id });

    res.status(201).json({
      success: true,
      data: workspace
    });
  } catch (error: any) {
    logger.error('Failed to create workspace', { error: error.message, userId: req.user?.id });
    res.status(500).json({
      success: false,
      error: 'Failed to create workspace'
    });
  }
};

export const getWorkspaces = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userWorkspaces = workspaces.filter(w => 
      w.userId === req.user!.id || 
      w.collaborators.some(c => c.userId === req.user!.id) ||
      (w.isPublic && req.query.includePublic === 'true')
    );

    res.json({
      success: true,
      data: userWorkspaces
    });
  } catch (error: any) {
    logger.error('Failed to get workspaces', { error: error.message, userId: req.user?.id });
    res.status(500).json({
      success: false,
      error: 'Failed to get workspaces'
    });
  }
};

export const getWorkspace = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    const workspace = workspaces.find(w => w.id === id);

    if (!workspace) {
      return res.status(404).json({
        success: false,
        error: 'Workspace not found'
      });
    }

    // Check permissions
    const hasAccess = workspace.userId === req.user!.id ||
      workspace.collaborators.some(c => c.userId === req.user!.id) ||
      workspace.isPublic;

    if (!hasAccess) {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    res.json({
      success: true,
      data: workspace
    });
  } catch (error: any) {
    logger.error('Failed to get workspace', { error: error.message, workspaceId: req.params.id });
    res.status(500).json({
      success: false,
      error: 'Failed to get workspace'
    });
  }
};

export const startWorkspace = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    const workspace = workspaces.find(w => w.id === id);

    if (!workspace) {
      return res.status(404).json({
        success: false,
        error: 'Workspace not found'
      });
    }

    // Check if user has permission to start workspace
    const hasPermission = workspace.userId === req.user!.id ||
      workspace.collaborators.some(c => c.userId === req.user!.id && ['owner', 'editor'].includes(c.role));

    if (!hasPermission) {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    // Find available port
    const usedPorts = sessions.filter(s => s.status === 'running').map(s => s.port);
    let port = config.codeServer.portRange.start;
    while (usedPorts.includes(port) && port <= config.codeServer.portRange.end) {
      port++;
    }

    if (port > config.codeServer.portRange.end) {
      return res.status(503).json({
        success: false,
        error: 'No available ports'
      });
    }

    // Create container
    const containerName = `codeserver-${workspace.id}-${Date.now()}`;
    
    const containerConfig = {
      Image: config.docker.defaultImage,
      name: containerName,
      ExposedPorts: {
        '8080/tcp': {}
      },
      HostConfig: {
        PortBindings: {
          '8080/tcp': [{ HostPort: port.toString() }]
        },
        Memory: parseMemory(workspace.resources.memory),
        CpuShares: parseInt(workspace.resources.cpu) * 1024,
        NetworkMode: config.docker.network
      },
      Env: [
        `PASSWORD=${config.codeServer.password}`,
        `WORKSPACE_ID=${workspace.id}`,
        `USER_ID=${req.user!.id}`,
        ...Object.entries(workspace.environment).map(([k, v]) => `${k}=${v}`)
      ],
      WorkingDir: '/workspace',
      Cmd: [
        '--bind-addr', '0.0.0.0:8080',
        '--auth', 'password',
        '--disable-telemetry',
        '/workspace'
      ]
    };

    const container = await docker.createContainer(containerConfig);
    await container.start();

    const session: Session = {
      id: uuidv4(),
      userId: req.user!.id,
      workspaceId: workspace.id,
      containerName,
      port,
      status: 'running',
      createdAt: new Date(),
      lastAccessed: new Date(),
      expiresAt: new Date(Date.now() + config.codeServer.defaultTimeout * 1000),
      resources: workspace.resources,
      environment: workspace.environment
    };

    sessions.push(session);

    // Update workspace last used
    workspace.lastUsed = new Date();

    auditLogger.log({
      id: uuidv4(),
      userId: req.user!.id,
      action: 'WORKSPACE_STARTED',
      resource: 'workspace',
      resourceId: workspace.id,
      details: { port, containerName },
      ip: req.ip,
      userAgent: req.get('User-Agent') || '',
      timestamp: new Date()
    });

    logger.info('Workspace started', { 
      workspaceId: workspace.id, 
      sessionId: session.id,
      port,
      userId: req.user!.id 
    });

    res.json({
      success: true,
      data: {
        session,
        url: `${config.codeServer.baseUrl}:${port}`
      }
    });
  } catch (error: any) {
    logger.error('Failed to start workspace', { 
      error: error.message, 
      workspaceId: req.params.id,
      userId: req.user?.id 
    });
    res.status(500).json({
      success: false,
      error: 'Failed to start workspace'
    });
  }
};

export const stopWorkspace = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    const session = sessions.find(s => s.workspaceId === id && s.status === 'running');

    if (!session) {
      return res.status(404).json({
        success: false,
        error: 'Active session not found'
      });
    }

    // Check permissions
    if (session.userId !== req.user!.id && req.user!.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    // Stop and remove container
    try {
      const container = docker.getContainer(session.containerName);
      await container.stop();
      await container.remove();
    } catch (dockerError: any) {
      logger.warn('Failed to stop container', { 
        error: dockerError.message, 
        containerName: session.containerName 
      });
    }

    session.status = 'stopped';

    auditLogger.log({
      id: uuidv4(),
      userId: req.user!.id,
      action: 'WORKSPACE_STOPPED',
      resource: 'workspace',
      resourceId: session.workspaceId,
      details: { sessionId: session.id },
      ip: req.ip,
      userAgent: req.get('User-Agent') || '',
      timestamp: new Date()
    });

    logger.info('Workspace stopped', { 
      workspaceId: session.workspaceId,
      sessionId: session.id,
      userId: req.user!.id 
    });

    res.json({
      success: true,
      message: 'Workspace stopped successfully'
    });
  } catch (error: any) {
    logger.error('Failed to stop workspace', { 
      error: error.message, 
      workspaceId: req.params.id,
      userId: req.user?.id 
    });
    res.status(500).json({
      success: false,
      error: 'Failed to stop workspace'
    });
  }
};

export const getSessions = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userSessions = sessions.filter(s => s.userId === req.user!.id);
    
    res.json({
      success: true,
      data: userSessions
    });
  } catch (error: any) {
    logger.error('Failed to get sessions', { error: error.message, userId: req.user?.id });
    res.status(500).json({
      success: false,
      error: 'Failed to get sessions'
    });
  }
};

export const deleteWorkspace = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    const workspaceIndex = workspaces.findIndex(w => w.id === id);

    if (workspaceIndex === -1) {
      return res.status(404).json({
        success: false,
        error: 'Workspace not found'
      });
    }

    const workspace = workspaces[workspaceIndex];

    // Check permissions - only owner or admin can delete
    if (workspace.userId !== req.user!.id && req.user!.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    // Stop any running sessions
    const runningSessions = sessions.filter(s => s.workspaceId === id && s.status === 'running');
    for (const session of runningSessions) {
      try {
        const container = docker.getContainer(session.containerName);
        await container.stop();
        await container.remove();
        session.status = 'stopped';
      } catch (dockerError: any) {
        logger.warn('Failed to stop container during workspace deletion', { 
          error: dockerError.message, 
          containerName: session.containerName 
        });
      }
    }

    // Mark workspace as deleted instead of actually deleting
    workspace.status = 'deleted';
    workspace.updatedAt = new Date();

    auditLogger.log({
      id: uuidv4(),
      userId: req.user!.id,
      action: 'WORKSPACE_DELETED',
      resource: 'workspace',
      resourceId: workspace.id,
      details: { name: workspace.name },
      ip: req.ip,
      userAgent: req.get('User-Agent') || '',
      timestamp: new Date()
    });

    logger.info('Workspace deleted', { 
      workspaceId: workspace.id,
      userId: req.user!.id 
    });

    res.json({
      success: true,
      message: 'Workspace deleted successfully'
    });
  } catch (error: any) {
    logger.error('Failed to delete workspace', { 
      error: error.message, 
      workspaceId: req.params.id,
      userId: req.user?.id 
    });
    res.status(500).json({
      success: false,
      error: 'Failed to delete workspace'
    });
  }
};

// Helper function to parse memory string to bytes
function parseMemory(memoryStr: string): number {
  const units: { [key: string]: number } = {
    'b': 1,
    'k': 1024,
    'm': 1024 * 1024,
    'g': 1024 * 1024 * 1024
  };
  
  const match = memoryStr.toLowerCase().match(/^(\d+)([bkmg]?)$/);
  if (!match) return 512 * 1024 * 1024; // Default 512MB
  
  const value = parseInt(match[1]);
  const unit = match[2] || 'b';
  
  return value * units[unit];
}
