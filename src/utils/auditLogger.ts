import { Request, Response, NextFunction } from 'express';
import { logger } from './logger';
import { AuthenticatedRequest } from '../auth/middleware';

interface AuditLogEntry {
  timestamp: string;
  userId?: string;
  action: string;
  resource: string;
  ip: string;
  userAgent: string;
  method: string;
  url: string;
  statusCode?: number;
  responseTime?: number;
  additionalData?: any;
}

export const auditLogger = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const startTime = Date.now();
  
  // Store original end function
  const originalEnd = res.end;
  
  // Override end function to capture response data
  res.end = function(chunk: any, encoding?: any) {
    const responseTime = Date.now() - startTime;
    
    const auditEntry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      userId: req.user?.id,
      action: `${req.method} ${req.url}`,
      resource: req.url,
      ip: req.ip || req.connection.remoteAddress || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      responseTime,
      additionalData: {
        body: req.body && Object.keys(req.body).length > 0 ? req.body : undefined,
        query: req.query && Object.keys(req.query).length > 0 ? req.query : undefined
      }
    };
    
    // Log security-relevant events
    if (req.url.includes('/auth') || req.url.includes('/admin') || res.statusCode >= 400) {
      logger.info('AUDIT:', auditEntry);
    }
    
    // Call original end function
    originalEnd.call(this, chunk, encoding);
  };
  
  next();
};

export const logSecurityEvent = (event: string, details: any) => {
  const securityEvent = {
    timestamp: new Date().toISOString(),
    event,
    details,
    severity: 'HIGH'
  };
  
  logger.warn('SECURITY EVENT:', securityEvent);
};

export const logWorkspaceActivity = (
  userId: string,
  workspaceId: string,
  action: string,
  details?: any
) => {
  const workspaceEvent = {
    timestamp: new Date().toISOString(),
    userId,
    workspaceId,
    action,
    details
  };
  
  logger.info('WORKSPACE ACTIVITY:', workspaceEvent);
};
