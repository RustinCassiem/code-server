import { Request, Response } from 'express';
import { Server as SocketIOServer } from 'socket.io';
import { v4 as uuidv4 } from 'uuid';
import { CollaborationSession, CollaborationParticipant, CursorPosition } from '../types';
import { logger } from '../utils/logger';
import { AuthenticatedRequest } from '../auth/middleware';

// In-memory storage for demo - replace with Redis/database in production
const collaborationSessions: Map<string, CollaborationSession> = new Map();

export class CollaborationController {
  private io: SocketIOServer;

  constructor(io: SocketIOServer) {
    this.io = io;
    this.setupSocketHandlers();
  }

  private setupSocketHandlers() {
    this.io.on('connection', (socket) => {
      logger.info('User connected for collaboration', { socketId: socket.id });

      socket.on('join-workspace', async (data: { workspaceId: string; user: any }) => {
        const { workspaceId, user } = data;
        
        socket.join(workspaceId);
        
        let session = collaborationSessions.get(workspaceId);
        if (!session) {
          session = {
            id: uuidv4(),
            workspaceId,
            participants: [],
            cursors: {},
            createdAt: new Date(),
            lastActivity: new Date()
          };
          collaborationSessions.set(workspaceId, session);
        }

        // Add or update participant
        const existingParticipantIndex = session.participants.findIndex(p => p.userId === user.id);
        const participant: CollaborationParticipant = {
          userId: user.id,
          username: user.username,
          avatar: user.avatar,
          role: 'editor', // This should be determined based on workspace permissions
          isActive: true,
          joinedAt: existingParticipantIndex === -1 ? new Date() : session.participants[existingParticipantIndex].joinedAt
        };

        if (existingParticipantIndex === -1) {
          session.participants.push(participant);
        } else {
          session.participants[existingParticipantIndex] = participant;
        }

        session.lastActivity = new Date();

        // Notify other participants
        socket.to(workspaceId).emit('user-joined', participant);
        
        // Send current session state to the new user
        socket.emit('session-state', {
          participants: session.participants,
          cursors: session.cursors,
          activeFile: session.activeFile
        });

        logger.info('User joined workspace collaboration', { 
          workspaceId, 
          userId: user.id,
          participantCount: session.participants.length 
        });
      });

      socket.on('cursor-update', (data: { workspaceId: string; cursor: CursorPosition; userId: string }) => {
        const { workspaceId, cursor, userId } = data;
        const session = collaborationSessions.get(workspaceId);
        
        if (session) {
          session.cursors[userId] = cursor;
          session.lastActivity = new Date();
          
          // Broadcast cursor position to other participants
          socket.to(workspaceId).emit('cursor-moved', { userId, cursor });
        }
      });

      socket.on('file-change', (data: { 
        workspaceId: string; 
        filePath: string; 
        changes: any; 
        userId: string 
      }) => {
        const { workspaceId, filePath, changes, userId } = data;
        const session = collaborationSessions.get(workspaceId);
        
        if (session) {
          session.lastActivity = new Date();
          
          // Broadcast file changes to other participants
          socket.to(workspaceId).emit('file-updated', {
            filePath,
            changes,
            userId,
            timestamp: new Date()
          });
          
          logger.debug('File change broadcast', { workspaceId, filePath, userId });
        }
      });

      socket.on('active-file-change', (data: { workspaceId: string; filePath: string; userId: string }) => {
        const { workspaceId, filePath, userId } = data;
        const session = collaborationSessions.get(workspaceId);
        
        if (session) {
          session.activeFile = filePath;
          session.lastActivity = new Date();
          
          // Broadcast active file change
          socket.to(workspaceId).emit('active-file-changed', { filePath, userId });
        }
      });

      socket.on('chat-message', (data: { 
        workspaceId: string; 
        message: string; 
        userId: string;
        username: string;
      }) => {
        const { workspaceId, message, userId, username } = data;
        
        const chatMessage = {
          id: uuidv4(),
          userId,
          username,
          message,
          timestamp: new Date()
        };
        
        // Broadcast chat message to all participants
        this.io.to(workspaceId).emit('chat-message', chatMessage);
        
        logger.info('Chat message sent', { workspaceId, userId, messageLength: message.length });
      });

      socket.on('leave-workspace', (data: { workspaceId: string; userId: string }) => {
        const { workspaceId, userId } = data;
        this.handleUserLeave(workspaceId, userId, socket);
      });

      socket.on('disconnect', () => {
        // Handle user disconnection - find all workspaces they were in
        // In a real implementation, you'd track socket-to-user mapping
        logger.info('User disconnected from collaboration', { socketId: socket.id });
      });
    });
  }

  private handleUserLeave(workspaceId: string, userId: string, socket: any) {
    const session = collaborationSessions.get(workspaceId);
    if (session) {
      // Mark participant as inactive
      const participant = session.participants.find(p => p.userId === userId);
      if (participant) {
        participant.isActive = false;
      }

      // Remove cursor
      delete session.cursors[userId];
      
      // Notify other participants
      socket.to(workspaceId).emit('user-left', { userId });
      
      // Clean up if no active participants
      const activeParticipants = session.participants.filter(p => p.isActive);
      if (activeParticipants.length === 0) {
        collaborationSessions.delete(workspaceId);
        logger.info('Collaboration session ended', { workspaceId });
      }
      
      socket.leave(workspaceId);
      logger.info('User left workspace collaboration', { workspaceId, userId });
    }
  }

  // REST API methods
  getCollaborationSession = (req: AuthenticatedRequest, res: Response) => {
    try {
      const { workspaceId } = req.params;
      const session = collaborationSessions.get(workspaceId);
      
      if (!session) {
        return res.status(404).json({
          success: false,
          error: 'Collaboration session not found'
        });
      }

      res.json({
        success: true,
        data: session
      });
    } catch (error: any) {
      logger.error('Failed to get collaboration session', { 
        error: error.message, 
        workspaceId: req.params.workspaceId 
      });
      res.status(500).json({
        success: false,
        error: 'Failed to get collaboration session'
      });
    }
  };

  getActiveCollaborations = (req: AuthenticatedRequest, res: Response) => {
    try {
      const userId = req.user!.id;
      const userSessions = Array.from(collaborationSessions.values())
        .filter(session => 
          session.participants.some(p => p.userId === userId && p.isActive)
        );

      res.json({
        success: true,
        data: userSessions
      });
    } catch (error: any) {
      logger.error('Failed to get active collaborations', { 
        error: error.message, 
        userId: req.user?.id 
      });
      res.status(500).json({
        success: false,
        error: 'Failed to get active collaborations'
      });
    }
  };

  inviteCollaborator = async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { workspaceId } = req.params;
      const { email, role } = req.body;

      // In a real implementation, you would:
      // 1. Check if the requesting user has permission to invite
      // 2. Look up the user by email
      // 3. Send an invitation email
      // 4. Store the invitation in the database

      // For now, we'll simulate this
      const invitation = {
        id: uuidv4(),
        workspaceId,
        inviterUserId: req.user!.id,
        inviteeEmail: email,
        role: role || 'viewer',
        status: 'pending',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
      };

      logger.info('Collaboration invitation sent', { 
        workspaceId, 
        inviterUserId: req.user!.id, 
        inviteeEmail: email 
      });

      res.json({
        success: true,
        data: invitation,
        message: 'Invitation sent successfully'
      });
    } catch (error: any) {
      logger.error('Failed to invite collaborator', { 
        error: error.message, 
        workspaceId: req.params.workspaceId 
      });
      res.status(500).json({
        success: false,
        error: 'Failed to invite collaborator'
      });
    }
  };
}

export default CollaborationController;
