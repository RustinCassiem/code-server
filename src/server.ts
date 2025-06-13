import express from 'express';
import { createServer } from 'http';
import { Server as SocketServer } from 'socket.io';
import session from 'express-session';
import passport from 'passport';
import helmet from 'helmet';
import cors from 'cors';
import { config } from './config';
import { logger } from './utils/logger';
import { auditLogger } from './utils/auditLogger';

// Route imports
import authRoutes from './routes/auth';
import apiRoutes from './routes/api';
import workspaceRoutes from './routes/workspace';
import collaborationRoutes from './routes/collaboration';
import adminRoutes from './routes/admin';

// Middleware imports
import { authenticateToken, rateLimitMiddleware } from './auth/middleware';

const app = express();
const httpServer = createServer(app);
const io = new SocketServer(httpServer, {
  cors: {
    origin: process.env.CLIENT_URL || "http://localhost:3001",
    methods: ["GET", "POST"]
  }
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "ws:", "wss:"],
    },
  },
}));

app.use(cors({
  origin: process.env.CLIENT_URL || "http://localhost:3001",
  credentials: true
}));

// Session configuration
app.use(session({
  secret: config.auth.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: config.nodeEnv === 'production',
    httpOnly: true,
    maxAge: config.security.sessionTimeout * 1000
  }
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Body parsing
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
app.use(rateLimitMiddleware);

// Audit logging
app.use(auditLogger);

// Routes
app.use('/auth', authRoutes);
app.use('/api', authenticateToken, apiRoutes);
app.use('/api/workspaces', authenticateToken, workspaceRoutes);
app.use('/api/collaboration', authenticateToken, collaborationRoutes);
app.use('/api/admin', authenticateToken, adminRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: process.env.npm_package_version || '1.0.0'
  });
});

// WebSocket handling for real-time collaboration
io.on('connection', (socket) => {
  logger.info(`User connected: ${socket.id}`);
  
  socket.on('join-workspace', (workspaceId) => {
    socket.join(workspaceId);
    socket.to(workspaceId).emit('user-joined', { userId: socket.id });
  });

  socket.on('code-change', (data) => {
    socket.to(data.workspaceId).emit('code-change', data);
  });

  socket.on('cursor-position', (data) => {
    socket.to(data.workspaceId).emit('cursor-position', data);
  });

  socket.on('disconnect', () => {
    logger.info(`User disconnected: ${socket.id}`);
  });
});

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({ 
    error: config.nodeEnv === 'production' ? 'Internal server error' : err.message 
  });
});

// Start the server
httpServer.listen(config.port, () => {
  logger.info(`Advanced Code Server running on port ${config.port}`);
  logger.info(`Environment: ${config.nodeEnv}`);
});