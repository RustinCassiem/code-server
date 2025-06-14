# CloudDev Server

A lightweight, security-driven cloud development environment server written in Go. This is a powerful alternative to Gitpod with enhanced security features and modern architecture.

## 🚀 Features

### Core Features
- **Container-based Workspaces**: Each workspace runs in an isolated Docker container
- **Web-based IDE**: Full-featured IDE accessible through your browser
- **Git Integration**: Built-in Git support with clone, commit, push, and pull operations
- **Real-time Collaboration**: Multiple users can work on the same workspace simultaneously
- **Terminal Access**: Full terminal access within workspace containers
- **File Management**: Complete file system operations through the web interface

### Security Features
- **Sandboxed Environments**: Each workspace runs in a secure, isolated container
- **Encrypted Connections**: All communications are encrypted using TLS
- **JWT Authentication**: Secure token-based authentication
- **Rate Limiting**: Built-in protection against abuse and DDoS attacks
- **Input Validation**: Comprehensive input sanitization and validation
- **Security Headers**: Proper security headers for all HTTP responses
- **Audit Logging**: Complete audit trail of all security events

### Enterprise Features
- **Multi-user Support**: Support for multiple users with proper access controls
- **Workspace Management**: Create, start, stop, and delete workspaces
- **Resource Limits**: Configurable CPU, memory, and disk limits per workspace
- **Monitoring**: Built-in metrics and health checks
- **Scalability**: Kubernetes-ready for horizontal scaling

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Browser   │────│  Nginx/Ingress  │────│  CloudDev API   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                              ┌─────────────────────────┼─────────────────────────┐
                              │                         │                         │
                    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
                    │   PostgreSQL    │    │      Redis      │    │  Docker Engine  │
                    │   (Database)    │    │    (Cache)      │    │  (Containers)   │
                    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🛠️ Technology Stack

- **Backend**: Go 1.21+ with Gin web framework
- **Database**: PostgreSQL 15+
- **Cache**: Redis 7+
- **Containerization**: Docker
- **Orchestration**: Kubernetes (optional)
- **Frontend**: HTML5, CSS3, JavaScript (embedded in Go binary)
- **Security**: JWT tokens, bcrypt password hashing, TLS encryption

## 📋 Prerequisites

- **Go**: 1.21 or higher
- **Docker**: 20.10 or higher
- **PostgreSQL**: 15 or higher
- **Redis**: 7 or higher

## 🚀 Quick Start

### Using Docker Compose (Recommended)

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd clouddev-server
   ```

2. **Start the services**:
   ```bash
   docker-compose up -d
   ```

3. **Access the application**:
   - Open your browser and navigate to `http://localhost:8080`
   - Default admin credentials: `admin@clouddev.local` / `admin123`

### Manual Installation

1. **Install dependencies**:
   ```bash
   go mod download
   ```

2. **Set up the database**:
   ```bash
   createdb clouddev
   psql clouddev < schema.sql
   ```

3. **Configure environment variables**:
   ```bash
   export DB_HOST=localhost
   export DB_USER=your_db_user
   export DB_PASSWORD=your_db_password
   export JWT_SECRET=your-secret-key
   ```

4. **Run the server**:
   ```bash
   go run main.go
   ```

## ⚙️ Configuration

The server can be configured using environment variables:

### Database Configuration
- `DB_HOST`: Database host (default: localhost)
- `DB_PORT`: Database port (default: 5432)
- `DB_NAME`: Database name (default: clouddev)
- `DB_USER`: Database user
- `DB_PASSWORD`: Database password
- `DB_SSL_MODE`: SSL mode (default: disable)

### Redis Configuration
- `REDIS_HOST`: Redis host (default: localhost)
- `REDIS_PORT`: Redis port (default: 6379)
- `REDIS_PASSWORD`: Redis password (optional)
- `REDIS_DB`: Redis database number (default: 0)

### Security Configuration
- `JWT_SECRET`: JWT signing secret (required)
- `TLS_CERT_PATH`: Path to TLS certificate
- `TLS_KEY_PATH`: Path to TLS private key
- `ENABLE_SANDBOX`: Enable container sandboxing (default: true)
- `RATE_LIMIT`: Requests per minute per IP (default: 100)

### Application Configuration
- `PORT`: Server port (default: 8080)
- `ENVIRONMENT`: Environment (development/production)
- `LOG_LEVEL`: Log level (debug/info/warn/error)
- `STORAGE_PATH`: Workspace storage path (default: ./data)

## 🔧 API Documentation

### Authentication Endpoints

```http
POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/me
```

### Workspace Endpoints

```http
GET    /api/v1/workspaces           # List workspaces
POST   /api/v1/workspaces           # Create workspace
GET    /api/v1/workspaces/:id       # Get workspace
PUT    /api/v1/workspaces/:id       # Update workspace
DELETE /api/v1/workspaces/:id       # Delete workspace
POST   /api/v1/workspaces/:id/start # Start workspace
POST   /api/v1/workspaces/:id/stop  # Stop workspace
GET    /api/v1/workspaces/:id/logs  # Get workspace logs
```

### IDE Endpoints

```http
GET    /api/v1/ide/:workspace_id                    # Access IDE
GET    /api/v1/ide/:workspace_id/files/*path        # Get file/directory
PUT    /api/v1/ide/:workspace_id/files/*path        # Save file
DELETE /api/v1/ide/:workspace_id/files/*path        # Delete file
POST   /api/v1/ide/:workspace_id/terminal           # Create terminal
```

### WebSocket Endpoint

```http
GET /api/v1/ws/:workspace_id?token=<jwt_token>
```

## 🐳 Docker Deployment

### Build Docker Image

```bash
docker build -t clouddev/server:latest .
```

### Run with Docker

```bash
docker run -d \
  --name clouddev-server \
  -p 8080:8080 \
  -e DB_HOST=your-db-host \
  -e DB_USER=your-db-user \
  -e DB_PASSWORD=your-db-password \
  -e JWT_SECRET=your-secret-key \
  -v /var/run/docker.sock:/var/run/docker.sock \
  clouddev/server:latest
```

## ☸️ Kubernetes Deployment

1. **Apply the deployments**:
   ```bash
   kubectl apply -f k8s/
   ```

2. **Check the status**:
   ```bash
   kubectl get pods -n clouddev
   ```

3. **Access the service**:
   ```bash
   kubectl port-forward service/clouddev-service 8080:80 -n clouddev
   ```

## 🔒 Security Considerations

### Production Deployment Checklist

- [ ] Change default admin password
- [ ] Generate secure JWT secret
- [ ] Enable TLS/HTTPS
- [ ] Configure proper firewall rules
- [ ] Set up database backups
- [ ] Enable audit logging
- [ ] Configure monitoring and alerting
- [ ] Update allowed origins for CORS
- [ ] Set resource limits for containers
- [ ] Enable container security scanning

### Security Features

1. **Container Isolation**: Each workspace runs in an isolated Docker container
2. **Network Security**: Containers use dedicated networks with restricted access
3. **File System Security**: Read-only root filesystem where possible
4. **User Security**: Non-root users in containers
5. **Input Validation**: All user inputs are validated and sanitized
6. **Rate Limiting**: Protection against brute force and DDoS attacks
7. **Security Headers**: Comprehensive HTTP security headers
8. **Audit Logging**: All security events are logged for analysis

## 📊 Monitoring

### Health Checks

The server provides a health check endpoint:

```http
GET /health
```

### Metrics

Prometheus metrics are available at:

```http
GET /metrics
```

Key metrics include:
- HTTP request duration and count
- Active WebSocket connections
- Container creation/deletion events
- Authentication attempts
- Security events

## 🧪 Testing

### Run Tests

```bash
go test ./...
```

### Run with Coverage

```bash
go test -cover ./...
```

### Integration Tests

```bash
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

## 📝 Development

### Project Structure

```
clouddev-server/
├── main.go                 # Application entry point
├── internal/              # Internal packages
│   ├── auth/              # Authentication service
│   ├── config/            # Configuration management
│   ├── container/         # Container orchestration
│   ├── git/               # Git integration
│   ├── ide/               # IDE service
│   └── workspace/         # Workspace management
├── pkg/                   # Public packages
│   ├── logger/            # Logging utilities
│   ├── models/            # Data models
│   ├── security/          # Security middleware
│   └── websocket/         # WebSocket handling
├── web/                   # Static web assets
├── k8s/                   # Kubernetes manifests
├── schema.sql             # Database schema
├── Dockerfile             # Docker build file
└── docker-compose.yml     # Docker Compose configuration
```

### Adding New Features

1. Create the feature in the appropriate package
2. Add tests for the feature
3. Update the API documentation
4. Add configuration options if needed
5. Update the database schema if required

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Documentation**: Check this README and code comments
- **Issues**: Report bugs and feature requests via GitHub issues
- **Security**: Report security issues privately to the maintainers

## 🎯 Roadmap

### Short Term
- [ ] Enhanced IDE features (syntax highlighting, autocomplete)
- [ ] More workspace templates
- [ ] Backup and restore functionality
- [ ] Enhanced collaboration features

### Medium Term
- [ ] Plugin system for IDE extensions
- [ ] Team workspaces
- [ ] Resource usage analytics
- [ ] Advanced Git workflows

### Long Term
- [ ] AI-powered coding assistance
- [ ] Multi-cloud deployment
- [ ] Enterprise SSO integration
- [ ] Advanced security features

---

**CloudDev Server** - Lightweight, Secure, and Powerful Cloud Development Environment
