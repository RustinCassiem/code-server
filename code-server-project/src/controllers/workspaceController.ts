import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { exec } from 'child_process';
import { promisify } from 'util';
import { config } from '../config';
import { logger } from '../utils/logger';
import { logWorkspaceActivity } from '../utils/auditLogger';
import { AuthenticatedRequest } from '../auth/middleware';
import { Workspace } from '../types';

const execAsync = promisify(exec);

// In-memory workspace store (replace with database in production)
const workspaces: Map<string, Workspace> = new Map();
const activeSessions: Map<string, any> = new Map();

export const createWorkspace = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { name, template, gitUrl, branch, resources } = req.body;
    const userId = req.user!.id;
    
    const workspace: Workspace = {
      id: uuidv4(),
      name,
      userId,
      gitUrl,
      branch: branch || 'main',
      template: template || 'node',
      resources: resources || {
        cpu: '1',
        memory: '2Gi',
        storage: '10Gi'
      },
      environment: {},
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    workspaces.set(workspace.id, workspace);
    
    // Create Docker container for workspace
    await createWorkspaceContainer(workspace);
    
    logWorkspaceActivity(userId, workspace.id, 'WORKSPACE_CREATED', { name, template });
    
    res.status(201).json(workspace);
  } catch (error) {
    logger.error('Error creating workspace:', error);
    res.status(500).json({ error: 'Failed to create workspace' });
  }
};

export const getWorkspaces = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userId = req.user!.id;
    const userWorkspaces = Array.from(workspaces.values())
      .filter(w => w.userId === userId || req.user!.role === 'admin');
    
    res.json(userWorkspaces);
  } catch (error) {
    logger.error('Error fetching workspaces:', error);
    res.status(500).json({ error: 'Failed to fetch workspaces' });
  }
};

export const getWorkspace = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    const workspace = workspaces.get(id);
    
    if (!workspace) {
      return res.status(404).json({ error: 'Workspace not found' });
    }
    
    if (workspace.userId !== req.user!.id && req.user!.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    res.json(workspace);
  } catch (error) {
    logger.error('Error fetching workspace:', error);
    res.status(500).json({ error: 'Failed to fetch workspace' });
  }
};

export const startWorkspace = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    const workspace = workspaces.get(id);
    
    if (!workspace) {
      return res.status(404).json({ error: 'Workspace not found' });
    }
    
    if (workspace.userId !== req.user!.id && req.user!.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Start the container
    const port = await getAvailablePort();
    const containerName = `workspace-${workspace.id}`;
    
    await execAsync(`docker start ${containerName}`);
    
    const session = {
      id: uuidv4(),
      userId: req.user!.id,
      workspaceId: workspace.id,
      containerName,
      port,
      status: 'running',
      createdAt: new Date(),
      lastAccessed: new Date()
    };
    
    activeSessions.set(session.id, session);
    
    logWorkspaceActivity(req.user!.id, workspace.id, 'WORKSPACE_STARTED');
    
    res.json({
      sessionId: session.id,
      url: `${config.codeServer.baseUrl}:${port}`,
      status: 'running'
    });
  } catch (error) {
    logger.error('Error starting workspace:', error);
    res.status(500).json({ error: 'Failed to start workspace' });
  }
};

export const stopWorkspace = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    const workspace = workspaces.get(id);
    
    if (!workspace) {
      return res.status(404).json({ error: 'Workspace not found' });
    }
    
    if (workspace.userId !== req.user!.id && req.user!.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const containerName = `workspace-${workspace.id}`;
    await execAsync(`docker stop ${containerName}`);
    
    // Remove active sessions
    for (const [sessionId, session] of activeSessions.entries()) {
      if (session.workspaceId === workspace.id) {
        activeSessions.delete(sessionId);
      }
    }
    
    logWorkspaceActivity(req.user!.id, workspace.id, 'WORKSPACE_STOPPED');
    
    res.json({ status: 'stopped' });
  } catch (error) {
    logger.error('Error stopping workspace:', error);
    res.status(500).json({ error: 'Failed to stop workspace' });
  }
};

export const deleteWorkspace = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    const workspace = workspaces.get(id);
    
    if (!workspace) {
      return res.status(404).json({ error: 'Workspace not found' });
    }
    
    if (workspace.userId !== req.user!.id && req.user!.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Stop and remove container
    const containerName = `workspace-${workspace.id}`;
    try {
      await execAsync(`docker stop ${containerName}`);
      await execAsync(`docker rm ${containerName}`);
    } catch (dockerError) {
      logger.warn('Container cleanup failed:', dockerError);
    }
    
    // Remove workspace and sessions
    workspaces.delete(id);
    for (const [sessionId, session] of activeSessions.entries()) {
      if (session.workspaceId === workspace.id) {
        activeSessions.delete(sessionId);
      }
    }
    
    logWorkspaceActivity(req.user!.id, workspace.id, 'WORKSPACE_DELETED');
    
    res.status(204).send();
  } catch (error) {
    logger.error('Error deleting workspace:', error);
    res.status(500).json({ error: 'Failed to delete workspace' });
  }
};

// Helper functions
async function createWorkspaceContainer(workspace: Workspace): Promise<void> {
  const containerName = `workspace-${workspace.id}`;
  const port = await getAvailablePort();
  
  let dockerImage = 'codercom/code-server:latest';
  
  // Select image based on template
  switch (workspace.template) {
    case 'node':
      dockerImage = 'codercom/code-server:latest';
      break;
    case 'python':
      dockerImage = 'codercom/code-server:latest';
      break;
    case 'java':
      dockerImage = 'codercom/code-server:latest';
      break;
    default:
      dockerImage = 'codercom/code-server:latest';
  }
  
  const dockerCommand = `
    docker run -d \
      --name ${containerName} \
      --network ${config.docker.network} \
      -p ${port}:8080 \
      -e PASSWORD=workspace-${workspace.id} \
      -v workspace-${workspace.id}:/home/coder/project \
      ${dockerImage} \
      --bind-addr 0.0.0.0:8080 \
      --auth password
  `.replace(/\s+/g, ' ').trim();
  
  await execAsync(dockerCommand);
  
  // If git URL provided, clone repository
  if (workspace.gitUrl) {
    await execAsync(`
      docker exec ${containerName} \
      git clone ${workspace.gitUrl} /home/coder/project/repo
    `);
  }
}

async function getAvailablePort(): Promise<number> {
  const { start, end } = config.codeServer.portRange;
  
  for (let port = start; port <= end; port++) {
    try {
      const { stdout } = await execAsync(`netstat -tuln | grep :${port}`);
      if (!stdout) {
        return port;
      }
    } catch (error) {
      return port; // Port is available
    }
  }
  
  throw new Error('No available ports in range');
}
