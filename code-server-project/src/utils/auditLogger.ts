import { AuditLog } from '../types';
import { logger } from './logger';
import { config } from '../config';

class AuditLogger {
  private logs: AuditLog[] = [];

  log(auditLog: AuditLog): void {
    if (!config.monitoring.enableAuditLog) {
      return;
    }

    this.logs.push(auditLog);
    
    // Log to winston logger
    logger.info('Audit Log', {
      type: 'audit',
      ...auditLog,
    });

    // In a real implementation, you would save to database
    // For now, we'll just keep in memory and log
    console.log('AUDIT:', JSON.stringify(auditLog, null, 2));
  }

  getLogs(userId?: string, action?: string, limit: number = 100): AuditLog[] {
    let filteredLogs = this.logs;

    if (userId) {
      filteredLogs = filteredLogs.filter(log => log.userId === userId);
    }

    if (action) {
      filteredLogs = filteredLogs.filter(log => log.action === action);
    }

    return filteredLogs
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  getLogsByResource(resource: string, resourceId?: string): AuditLog[] {
    return this.logs.filter(log => {
      if (resourceId) {
        return log.resource === resource && log.resourceId === resourceId;
      }
      return log.resource === resource;
    });
  }
}

export const auditLogger = new AuditLogger();
export default auditLogger;
