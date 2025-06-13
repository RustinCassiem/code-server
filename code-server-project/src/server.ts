import express from 'express';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import session from 'express-session';
import Redis from 'ioredis';
import connectRedis from 'connect-redis';
import promBundle from 'express-prom-bundle';

import { config, configureDatabase } from './config';
import { logger } from './utils/logger';
import { 
  rateLimitMiddleware, 
  corsMiddleware, 
  securityHeaders, 
  auditMiddleware 
} from './auth/middleware';

// Import routes
import authRoutes from './routes/auth';
import apiRoutes from './routes/api';
import workspaceRoutes from './routes/workspace';
import collaborationRoutes from './routes/collaboration';
import adminRoutes from './routes/admin';

// Import controllers
import CollaborationController from './controllers/collaborationController';

const app = express();
const server = createServer(app);

// Socket.IO setup
const io = new SocketIOServer(server, {
  cors: {
    origin: config.security.allowedOrigins,
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Redis setup for sessions
const redisClient = new Redis({
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password,
  db: config.redis.db,
});

const RedisStore = connectRedis(session);

// Prometheus metrics (if enabled)
if (config.monitoring.enableMetrics) {
  const metricsMiddleware = promBundle({
    includeMethod: true,
    includePath: true,
    includeStatusCode: true,
    includeUp: true,
    customLabels: { project_name: 'advanced-code-server' },
    promClient: {
      collectDefaultMetrics: {},
    },
  });
  app.use(metricsMiddleware);
}

// Basic middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "ws:", "wss:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
}));

app.use(compression());
app.use(corsMiddleware);
app.use(securityHeaders);
app.use(express.json({ limit: `${config.security.maxFileSize}mb` }));
app.use(express.urlencoded({ extended: true, limit: `${config.security.maxFileSize}mb` }));

// Session middleware
app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: config.auth.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: config.nodeEnv === 'production',
    httpOnly: true,
    maxAge: config.security.sessionTimeout * 1000,
    sameSite: 'strict'
  },
  name: 'codeserver.sid'
}));

// Rate limiting
app.use(rateLimitMiddleware);

// Audit logging
app.use(auditMiddleware);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0',
    environment: config.nodeEnv
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api', apiRoutes);
app.use('/api/workspaces', workspaceRoutes);
app.use('/api/collaboration', collaborationRoutes);
app.use('/api/admin', adminRoutes);

// Initialize collaboration controller
const collaborationController = new CollaborationController(io);

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  logger.error('Unhandled error:', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip
  });

  res.status(err.status || 500).json({
    success: false,
    error: config.nodeEnv === 'production' ? 'Internal server error' : err.message
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found'
  });
});

// Database configuration
configureDatabase();

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Server closed');
    redisClient.disconnect();
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  server.close(() => {
    logger.info('Server closed');
    redisClient.disconnect();
    process.exit(0);
  });
});

// Unhandled promise rejection
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', { promise, reason });
  process.exit(1);
});

// Uncaught exception
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', { error: error.message, stack: error.stack });
  process.exit(1);
});

// Start the server
const PORT = config.port;
server.listen(PORT, () => {
  logger.info(`Advanced Code Server started on port ${PORT}`, {
    environment: config.nodeEnv,
    features: config.features,
    metricsEnabled: config.monitoring.enableMetrics
  });
  console.log(`🚀 Advanced Code Server running on http://localhost:${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  if (config.monitoring.enableMetrics) {
    console.log(`📈 Metrics: http://localhost:${PORT}/metrics`);
  }
});

export default app;