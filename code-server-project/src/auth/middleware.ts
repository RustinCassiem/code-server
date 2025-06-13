import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { RateLimiterRedis } from 'rate-limiter-flexible';
import Redis from 'redis';
import { config } from '../config';
import { User } from '../types';
import { logger } from '../utils/logger';

const redisClient = Redis.createClient({
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password,
});

const rateLimiter = new RateLimiterRedis({
  storeClient: redisClient,
  keyPrefix: 'login_fail',
  points: config.security.maxLoginAttempts,
  duration: config.security.lockoutDuration,
});

export interface AuthenticatedRequest extends Request {
  user?: User;
}

export const authenticateToken = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, config.auth.jwtSecret) as any;
    req.user = decoded.user;
    next();
  } catch (error) {
    logger.warn(`Invalid token attempt from IP: ${req.ip}`);
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

export const requireRole = (roles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) {
      logger.warn(`Insufficient permissions for user ${req.user?.id} from IP: ${req.ip}`);
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

export const rateLimitMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    await rateLimiter.consume(req.ip);
    next();
  } catch (rejRes) {
    const secs = Math.round(rejRes.msBeforeNext / 1000) || 1;
    res.set('Retry-After', String(secs));
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({ error: 'Too many requests', retryAfter: secs });
  }
};

export const validateWorkspaceAccess = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  const workspaceId = req.params.workspaceId;
  const userId = req.user?.id;
  
  // TODO: Implement workspace access validation logic
  // Check if user has access to workspace in database
  
  next();
};

export const auditLog = (action: string) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    logger.info(`Audit: ${action} by user ${req.user?.id} from IP ${req.ip}`);
    next();
  };
};