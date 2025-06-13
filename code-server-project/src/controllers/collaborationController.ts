import { Request, Response } from 'express';
import { AuthenticatedRequest } from '../auth/middleware';
import { logger } from '../utils/logger';

interface CollaborationSession {
  id: string;
  workspaceId: string;
  users: {
    userId: string;
    username: string;
    cursor?: { line: number; column: number };
    selection?: { start: any; end: any };
    color: string;
  }[];
  createdAt: Date;
}

// In-memory collaboration sessions
const collaborationSessions: Map<string, CollaborationSession> = new Map();

export const joinCollaboration = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { workspaceId } = req.params;
    const userId = req.user!.id;
    const username = req.user!.username;
    
    let session = collaborationSessions.get(workspaceId);
    
    if (!session) {
      session = {
        id: workspaceId,
        workspaceId,
        users: [],
        createdAt: new Date()
      };
      collaborationSessions.set(workspaceId, session);
    }
    
    // Check if user already in session
    const existingUser = session.users.find(u => u.userId === userId);
    if (!existingUser) {
      const colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7'];
      const color = colors[session.users.length % colors.length];
      
      session.users.push({
        userId,
        username,
        color
      });
    }
    
    res.json({
      sessionId: session.id,
      users: session.users,
      message: 'Joined collaboration session'
    });
    
    logger.info(`User ${username} joined collaboration for workspace ${workspaceId}`);
  } catch (error) {
    logger.error('Error joining collaboration:', error);
    res.status(500).json({ error: 'Failed to join collaboration' });
  }
};

export const leaveCollaboration = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { workspaceId } = req.params;
    const userId = req.user!.id;
    
    const session = collaborationSessions.get(workspaceId);
    if (session) {
      session.users = session.users.filter(u => u.userId !== userId);
      
      if (session.users.length === 0) {
        collaborationSessions.delete(workspaceId);
      }
    }
    
    res.json({ message: 'Left collaboration session' });
    
    logger.info(`User ${req.user!.username} left collaboration for workspace ${workspaceId}`);
  } catch (error) {
    logger.error('Error leaving collaboration:', error);
    res.status(500).json({ error: 'Failed to leave collaboration' });
  }
};

export const getCollaborationStatus = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { workspaceId } = req.params;
    const session = collaborationSessions.get(workspaceId);
    
    res.json({
      isActive: !!session,
      users: session?.users || [],
      userCount: session?.users.length || 0
    });
  } catch (error) {
    logger.error('Error getting collaboration status:', error);
    res.status(500).json({ error: 'Failed to get collaboration status' });
  }
};

export const updateCursor = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { workspaceId } = req.params;
    const { line, column } = req.body;
    const userId = req.user!.id;
    
    const session = collaborationSessions.get(workspaceId);
    if (session) {
      const user = session.users.find(u => u.userId === userId);
      if (user) {
        user.cursor = { line, column };
      }
    }
    
    res.json({ message: 'Cursor updated' });
  } catch (error) {
    logger.error('Error updating cursor:', error);
    res.status(500).json({ error: 'Failed to update cursor' });
  }
};

export const shareWorkspace = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { workspaceId } = req.params;
    const { email, permission } = req.body;
    
    // TODO: Implement workspace sharing logic
    // - Generate share link or invite
    // - Set permissions (read, write, admin)
    // - Send email invitation
    
    const shareLink = `${req.protocol}://${req.get('host')}/workspace/${workspaceId}/shared?token=example-token`;
    
    res.json({
      shareLink,
      permission,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
    });
    
    logger.info(`Workspace ${workspaceId} shared with ${email} by ${req.user!.username}`);
  } catch (error) {
    logger.error('Error sharing workspace:', error);
    res.status(500).json({ error: 'Failed to share workspace' });
  }
};
