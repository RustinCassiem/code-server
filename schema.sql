-- CloudDev Database Schema
-- This file contains the complete database schema for the CloudDev server

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Workspaces table
CREATE TABLE IF NOT EXISTS workspaces (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'created',
    image VARCHAR(255) NOT NULL DEFAULT 'clouddev/workspace:latest',
    git_url TEXT,
    git_branch VARCHAR(255) DEFAULT 'main',
    container_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_status CHECK (status IN ('created', 'running', 'stopped', 'error'))
);

-- Sessions table for authentication
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    workspace_id VARCHAR(255) REFERENCES workspaces(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Files table for workspace files metadata
CREATE TABLE IF NOT EXISTS files (
    id VARCHAR(255) PRIMARY KEY,
    workspace_id VARCHAR(255) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    content TEXT,
    size BIGINT DEFAULT 0,
    mime_type VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(workspace_id, path)
);

-- Terminals table for terminal sessions
CREATE TABLE IF NOT EXISTS terminals (
    id VARCHAR(255) PRIMARY KEY,
    workspace_id VARCHAR(255) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id VARCHAR(255) NOT NULL,
    command VARCHAR(255) NOT NULL,
    args TEXT[], -- PostgreSQL array for arguments
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_terminal_status CHECK (status IN ('active', 'closed'))
);

-- Collaboration table for real-time collaboration tracking
CREATE TABLE IF NOT EXISTS collaboration (
    id VARCHAR(255) PRIMARY KEY,
    workspace_id VARCHAR(255) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    operation VARCHAR(50) NOT NULL,
    changes TEXT, -- JSON encoded changes
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_operation CHECK (operation IN ('edit', 'create', 'delete'))
);

-- Security events table for audit logging
CREATE TABLE IF NOT EXISTS security_events (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) REFERENCES users(id) ON DELETE SET NULL,
    workspace_id VARCHAR(255) REFERENCES workspaces(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'low',
    message TEXT NOT NULL,
    client_ip INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_severity CHECK (severity IN ('low', 'medium', 'high', 'critical'))
);

-- Workspace permissions table (for future use)
CREATE TABLE IF NOT EXISTS workspace_permissions (
    id VARCHAR(255) PRIMARY KEY,
    workspace_id VARCHAR(255) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission VARCHAR(50) NOT NULL,
    granted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    granted_by VARCHAR(255) NOT NULL REFERENCES users(id),
    UNIQUE(workspace_id, user_id, permission),
    CONSTRAINT valid_permission CHECK (permission IN ('read', 'write', 'admin'))
);

-- API keys table (for programmatic access)
CREATE TABLE IF NOT EXISTS api_keys (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    permissions TEXT[], -- Array of permissions
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Workspace snapshots table (for backup/restore)
CREATE TABLE IF NOT EXISTS workspace_snapshots (
    id VARCHAR(255) PRIMARY KEY,
    workspace_id VARCHAR(255) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    snapshot_path TEXT NOT NULL,
    size_bytes BIGINT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_workspaces_user_id ON workspaces(user_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_status ON workspaces(status);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_files_workspace_id ON files(workspace_id);
CREATE INDEX IF NOT EXISTS idx_files_path ON files(workspace_id, path);
CREATE INDEX IF NOT EXISTS idx_terminals_workspace_id ON terminals(workspace_id);
CREATE INDEX IF NOT EXISTS idx_terminals_user_id ON terminals(user_id);
CREATE INDEX IF NOT EXISTS idx_collaboration_workspace_id ON collaboration(workspace_id);
CREATE INDEX IF NOT EXISTS idx_collaboration_created_at ON collaboration(created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_workspace_permissions_workspace_id ON workspace_permissions(workspace_id);
CREATE INDEX IF NOT EXISTS idx_workspace_permissions_user_id ON workspace_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_workspace_snapshots_workspace_id ON workspace_snapshots(workspace_id);

-- Triggers for updating updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_workspaces_updated_at BEFORE UPDATE ON workspaces
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_files_updated_at BEFORE UPDATE ON files
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_terminals_updated_at BEFORE UPDATE ON terminals
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM sessions WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get workspace statistics
CREATE OR REPLACE FUNCTION get_workspace_stats(p_workspace_id VARCHAR(255))
RETURNS TABLE(
    file_count BIGINT,
    total_size BIGINT,
    last_activity TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(f.id)::BIGINT as file_count,
        COALESCE(SUM(f.size), 0)::BIGINT as total_size,
        MAX(GREATEST(f.created_at, f.updated_at)) as last_activity
    FROM files f
    WHERE f.workspace_id = p_workspace_id;
END;
$$ LANGUAGE plpgsql;

-- View for user workspace summary
CREATE OR REPLACE VIEW user_workspace_summary AS
SELECT 
    u.id as user_id,
    u.email,
    u.name,
    COUNT(w.id) as workspace_count,
    COUNT(CASE WHEN w.status = 'running' THEN 1 END) as running_workspaces,
    MAX(w.updated_at) as last_workspace_activity
FROM users u
LEFT JOIN workspaces w ON u.id = w.user_id
GROUP BY u.id, u.email, u.name;

-- View for workspace details with user info
CREATE OR REPLACE VIEW workspace_details AS
SELECT 
    w.*,
    u.email as user_email,
    u.name as user_name,
    (SELECT COUNT(*) FROM files f WHERE f.workspace_id = w.id) as file_count,
    (SELECT COUNT(*) FROM terminals t WHERE t.workspace_id = w.id AND t.status = 'active') as active_terminals
FROM workspaces w
JOIN users u ON w.user_id = u.id;

-- Insert default admin user (password: admin123 - change in production!)
INSERT INTO users (id, email, name, password_hash) 
VALUES (
    'admin-' || extract(epoch from now()),
    'admin@clouddev.local', 
    'Administrator',
    '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'
) ON CONFLICT (email) DO NOTHING;

-- Create initial workspace image entries (metadata only)
CREATE TABLE IF NOT EXISTS workspace_images (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    tag VARCHAR(255) NOT NULL DEFAULT 'latest',
    description TEXT,
    dockerfile_path TEXT,
    size_bytes BIGINT DEFAULT 0,
    is_public BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(name, tag)
);

-- Insert default workspace images
INSERT INTO workspace_images (id, name, tag, description) VALUES
('img-ubuntu-latest', 'ubuntu', 'latest', 'Ubuntu 22.04 with basic development tools'),
('img-node-latest', 'node', 'latest', 'Node.js development environment'),
('img-python-latest', 'python', 'latest', 'Python development environment'),
('img-go-latest', 'golang', 'latest', 'Go development environment'),
('img-rust-latest', 'rust', 'latest', 'Rust development environment')
ON CONFLICT (name, tag) DO NOTHING;
