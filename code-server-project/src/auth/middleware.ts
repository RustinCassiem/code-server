import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { RateLimiterRedis } from 'rate-limiter-flexible';
import Redis from 'ioredis';
import bcrypt from 'bcryptjs';
import speakeasy from 'speakeasy';
import { config } from '../config';
import { User, AuditLog } from '../types';

const redisClient = new Redis({
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password,
  db: config.redis.db,
  keyPrefix: config.redis.keyPrefix,
});

// Rate limiters for different scenarios
const loginRateLimiter = new RateLimiterRedis({
  storeClient: redisClient,
  keyPrefix: 'login_fail',
  points: config.security.maxLoginAttempts,
  duration: config.security.lockoutDuration,
  blockDuration: config.security.lockoutDuration,
});

const apiRateLimiter = new RateLimiterRedis({
  storeClient: redisClient,
  keyPrefix: 'api_rate',
  points: config.security.rateLimitRequests,
  duration: config.security.rateLimitWindow,
});

export interface AuthenticatedRequest extends Request {
  user?: User;
  sessionId?: string;
}

export const authenticateToken = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, config.auth.jwtSecret) as any;
    
    // Check if user is still active and not banned
    const userKey = `user:${decoded.userId}`;
    const userDataStr = await redisClient.get(userKey);
    
    if (!userDataStr) {
      return res.status(403).json({ error: 'User session expired' });
    }

    const userData = JSON.parse(userDataStr);
    
    if (!userData.isActive || userData.isBanned) {
      return res.status(403).json({ error: 'User account is inactive or banned' });
    }

    req.user = userData;
    req.sessionId = decoded.sessionId;

    // Update last activity
    await redisClient.setex(userKey, config.security.sessionTimeout, JSON.stringify({
      ...userData,
      lastActivity: new Date(),
    }));

    next();
  } catch (error: any) {
    console.warn('Authentication failed:', { error: error.message, ip: req.ip });
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

export const requireRole = (roles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) {
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
    await apiRateLimiter.consume(req.ip);
    next();
  } catch (rejRes: any) {
    const secs = Math.round(rejRes.msBeforeNext / 1000) || 1;
    res.set('Retry-After', String(secs));
    console.warn('Rate limit exceeded:', { ip: req.ip, path: req.path });
    return res.status(429).json({ 
      error: 'Too many requests', 
      retryAfter: secs 
    });
  }
};

export const loginRateLimit = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    await loginRateLimiter.consume(req.ip);
    next();
  } catch (rejRes: any) {
    const secs = Math.round(rejRes.msBeforeNext / 1000) || 1;
    res.set('Retry-After', String(secs));
    console.warn('Login rate limit exceeded:', { ip: req.ip });
    return res.status(429).json({ 
      error: 'Too many login attempts', 
      retryAfter: secs 
    });
  }
};

export const validatePassword = (password: string): { valid: boolean; errors: string[] } => {
  const errors: string[] = [];
  
  if (password.length < config.security.passwordMinLength) {
    errors.push(`Password must be at least ${config.security.passwordMinLength} characters long`);
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
};

export const hashPassword = async (password: string): Promise<string> => {
  const saltRounds = 12;
  return bcrypt.hash(password, saltRounds);
};

export const comparePassword = async (password: string, hash: string): Promise<boolean> => {
  return bcrypt.compare(password, hash);
};

export const generateJWT = (user: User, sessionId: string): string => {
  return jwt.sign(
    { 
      userId: user.id, 
      username: user.username,
      role: user.role,
      sessionId,
    },
    config.auth.jwtSecret,
    { expiresIn: config.auth.tokenExpiration }
  );
};

export const protectRoute = (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) return res.sendStatus(401); // Unauthorized
    next();
};