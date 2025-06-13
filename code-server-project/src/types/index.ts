export interface User {
  id: string;
  username: string;
  email: string;
  password?: string;
  passwordHash?: string;
  role: 'admin' | 'user' | 'readonly' | 'moderator';
  githubId?: string;
  googleId?: string;
  twoFactorSecret?: string;
  twoFactorEnabled: boolean;
  emailVerified: boolean;
  avatar?: string;
  preferences: UserPreferences;
  createdAt: Date;
  updatedAt: Date;
  lastLogin?: Date;
  lastActivity?: Date;
  isActive: boolean;
  isBanned: boolean;
  subscription?: UserSubscription;
}

export interface UserPreferences {
  theme: 'light' | 'dark' | 'auto';
  language: string;
  timezone: string;
  notifications: {
    email: boolean;
    push: boolean;
    collaboration: boolean;
  };
  editor: {
    fontSize: number;
    tabSize: number;
    wordWrap: boolean;
    minimap: boolean;
  };
}

export interface UserSubscription {
  plan: 'free' | 'pro' | 'enterprise';
  status: 'active' | 'cancelled' | 'expired';
  validUntil?: Date;
  features: string[];
}

export interface Session {
  id: string;
  userId: string;
  workspaceId: string;
  containerName: string;
  port: number;
  status: 'running' | 'stopped' | 'error' | 'starting' | 'stopping';
  createdAt: Date;
  lastAccessed: Date;
  expiresAt: Date;
  resources: ContainerResources;
  environment: Record<string, string>;
}

export interface ContainerResources {
  cpu: string;
  memory: string;
  storage: string;
  networkMode: string;
}

export interface Workspace {
  id: string;
  name: string;
  description?: string;
  userId: string;
  gitUrl?: string;
  branch?: string;
  template: string;
  templateVersion: string;
  resources: ContainerResources;
  environment: Record<string, string>;
  extensions: string[];
  settings: WorkspaceSettings;
  collaborators: WorkspaceCollaborator[];
  isPublic: boolean;
  tags: string[];
  createdAt: Date;
  updatedAt: Date;
  lastUsed?: Date;
  status: 'active' | 'archived' | 'deleted';
}

export interface WorkspaceSettings {
  autoSave: boolean;
  autoStop: number; // minutes of inactivity
  maxFileSize: number; // MB
  allowedExtensions: string[];
  blockedExtensions: string[];
}

export interface WorkspaceCollaborator {
  userId: string;
  role: 'owner' | 'editor' | 'viewer';
  invitedAt: Date;
  acceptedAt?: Date;
  invitedBy: string;
}

export interface WorkspaceTemplate {
  id: string;
  name: string;
  description: string;
  dockerImage: string;
  category: string;
  tags: string[];
  defaultExtensions: string[];
  defaultSettings: WorkspaceSettings;
  icon?: string;
  isOfficial: boolean;
  createdBy: string;
  downloads: number;
  rating: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface AuthConfig {
  jwtSecret: string;
  sessionSecret: string;
  github: {
    clientId: string;
    clientSecret: string;
  };
  google: {
    clientId: string;
    clientSecret: string;
  };
  oauth2: {
    clientId: string;
    clientSecret: string;
    authorizationURL: string;
    tokenURL: string;
  };
}

export interface CollaborationSession {
  id: string;
  workspaceId: string;
  participants: CollaborationParticipant[];
  activeFile?: string;
  cursors: Record<string, CursorPosition>;
  createdAt: Date;
  lastActivity: Date;
}

export interface CollaborationParticipant {
  userId: string;
  username: string;
  avatar?: string;
  role: 'owner' | 'editor' | 'viewer';
  cursor?: CursorPosition;
  isActive: boolean;
  joinedAt: Date;
}

export interface CursorPosition {
  line: number;
  column: number;
  selection?: {
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
  };
}

export interface FileSystemItem {
  id: string;
  name: string;
  path: string;
  type: 'file' | 'directory';
  size?: number;
  mimeType?: string;
  lastModified: Date;
  permissions: FilePermissions;
  isHidden: boolean;
  parent?: string;
  children?: string[];
}

export interface FilePermissions {
  read: boolean;
  write: boolean;
  execute: boolean;
  owner: string;
}

export interface AuditLog {
  id: string;
  userId: string;
  action: string;
  resource: string;
  resourceId: string;
  details: Record<string, any>;
  ip: string;
  userAgent: string;
  timestamp: Date;
}

export interface Notification {
  id: string;
  userId: string;
  type: 'info' | 'warning' | 'error' | 'success';
  title: string;
  message: string;
  data?: Record<string, any>;
  read: boolean;
  createdAt: Date;
  expiresAt?: Date;
}

export interface SystemMetrics {
  cpu: {
    usage: number;
    cores: number;
  };
  memory: {
    used: number;
    total: number;
    free: number;
  };
  disk: {
    used: number;
    total: number;
    free: number;
  };
  network: {
    bytesIn: number;
    bytesOut: number;
  };
  containers: {
    running: number;
    stopped: number;
    total: number;
  };
  timestamp: Date;
}

export interface AuthToken {
    token: string;
    expiresIn: number;
}

export interface ApiResponse<T> {
    success: boolean;
    data?: T;
    error?: string;
}

export interface LoginRequest {
    username: string;
    password: string;
    twoFactorCode?: string;
}

export interface RegisterRequest {
    username: string;
    email: string;
    password: string;
}