import dotenv from 'dotenv';
import { AuthConfig } from '../types';

dotenv.config();

export const config = {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  
  auth: {
    jwtSecret: process.env.JWT_SECRET || 'your-jwt-secret-change-in-production',
    sessionSecret: process.env.SESSION_SECRET || 'your-session-secret-change-in-production',
    tokenExpiration: process.env.TOKEN_EXPIRATION || '24h',
    refreshTokenExpiration: process.env.REFRESH_TOKEN_EXPIRATION || '7d',
    github: {
      clientId: process.env.GITHUB_CLIENT_ID || '',
      clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
    },
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
    },
    oauth2: {
      clientId: process.env.OAUTH2_CLIENT_ID || '',
      clientSecret: process.env.OAUTH2_CLIENT_SECRET || '',
      authorizationURL: process.env.OAUTH2_AUTH_URL || '',
      tokenURL: process.env.OAUTH2_TOKEN_URL || '',
    },
  } as AuthConfig,

  database: {
    type: process.env.DB_TYPE || 'sqlite',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432'),
    username: process.env.DB_USERNAME || '',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'codeserver',
    url: process.env.DATABASE_URL || 'sqlite:./database.sqlite',
    ssl: process.env.DB_SSL === 'true',
    logging: process.env.DB_LOGGING === 'true',
  },

  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD,
    db: parseInt(process.env.REDIS_DB || '0'),
    keyPrefix: process.env.REDIS_KEY_PREFIX || 'codeserver:',
  },

  codeServer: {
    baseUrl: process.env.CODE_SERVER_BASE_URL || 'http://localhost',
    password: process.env.CODE_SERVER_PASSWORD || '',
    portRange: {
      start: parseInt(process.env.PORT_RANGE_START || '8080'),
      end: parseInt(process.env.PORT_RANGE_END || '8180'),
    },
    defaultTimeout: parseInt(process.env.DEFAULT_TIMEOUT || '1800'), // 30 minutes
    maxInstances: parseInt(process.env.MAX_INSTANCES || '100'),
  },

  docker: {
    network: process.env.DOCKER_NETWORK || 'code-server-network',
    registryUrl: process.env.DOCKER_REGISTRY_URL || 'docker.io',
    defaultImage: process.env.DEFAULT_DOCKER_IMAGE || 'codercom/code-server:latest',
    volumePath: process.env.VOLUME_PATH || '/workspaces',
    socketPath: process.env.DOCKER_SOCKET || '/var/run/docker.sock',
  },

  security: {
    maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5'),
    lockoutDuration: parseInt(process.env.LOCKOUT_DURATION || '900'), // 15 minutes
    sessionTimeout: parseInt(process.env.SESSION_TIMEOUT || '3600'), // 1 hour
    passwordMinLength: parseInt(process.env.PASSWORD_MIN_LENGTH || '8'),
    requireTwoFactor: process.env.REQUIRE_TWO_FACTOR === 'true',
    allowedOrigins: (process.env.ALLOWED_ORIGINS || '*').split(','),
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '100'), // MB
    rateLimitRequests: parseInt(process.env.RATE_LIMIT_REQUESTS || '100'),
    rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW || '900'), // 15 minutes
  },

  email: {
    host: process.env.EMAIL_HOST || '',
    port: parseInt(process.env.EMAIL_PORT || '587'),
    secure: process.env.EMAIL_SECURE === 'true',
    username: process.env.EMAIL_USERNAME || '',
    password: process.env.EMAIL_PASSWORD || '',
    from: process.env.EMAIL_FROM || 'noreply@codeserver.dev',
  },

  storage: {
    provider: process.env.STORAGE_PROVIDER || 'local',
    bucket: process.env.STORAGE_BUCKET || '',
    region: process.env.STORAGE_REGION || '',
    accessKey: process.env.STORAGE_ACCESS_KEY || '',
    secretKey: process.env.STORAGE_SECRET_KEY || '',
    endpoint: process.env.STORAGE_ENDPOINT || '',
  },

  monitoring: {
    enableMetrics: process.env.ENABLE_METRICS === 'true',
    metricsPort: parseInt(process.env.METRICS_PORT || '9090'),
    logLevel: process.env.LOG_LEVEL || 'info',
    enableAuditLog: process.env.ENABLE_AUDIT_LOG === 'true',
  },

  features: {
    collaboration: process.env.ENABLE_COLLABORATION === 'true',
    fileSharing: process.env.ENABLE_FILE_SHARING === 'true',
    terminalSharing: process.env.ENABLE_TERMINAL_SHARING === 'true',
    liveShare: process.env.ENABLE_LIVE_SHARE === 'true',
    extensionMarketplace: process.env.ENABLE_EXTENSION_MARKETPLACE === 'true',
    gitIntegration: process.env.ENABLE_GIT_INTEGRATION === 'true',
  },
};

export const configureDatabase = () => {
  // Database configuration logic will be implemented here
  console.log('Database configured:', config.database.type);
};

// Legacy support
const legacyConfig = {
    port: config.port,
    db: {
        host: config.database.host,
        port: config.database.port,
        user: config.database.username,
        password: config.database.password,
        database: config.database.database,
    },
    jwt: {
        secret: config.auth.jwtSecret,
        expiresIn: config.auth.tokenExpiration,
    },
    oauth: {
        clientID: config.auth.oauth2.clientId,
        clientSecret: config.auth.oauth2.clientSecret,
        callbackURL: process.env.OAUTH_CALLBACK_URL || 'http://localhost:3000/auth/callback',
    },
};

export default legacyConfig;