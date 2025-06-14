# Copilot Instructions

<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

This is a cloud development environment server project written in Go. The goal is to create a lightweight, security-driven alternative to Gitpod with enhanced features:

## Project Goals
- Build a containerized cloud development environment
- Implement strong security features including sandboxing and encrypted connections
- Provide web-based IDE integration
- Support real-time collaboration
- Include comprehensive workspace management
- Implement robust authentication and authorization
- Support Git integration and version control
- Deploy using Docker and Kubernetes

## Key Technologies
- Go for the main server implementation
- Docker for containerization
- Kubernetes for orchestration
- WebSocket for real-time communication
- JWT for authentication
- PostgreSQL for data persistence
- Redis for caching and session management

## Security Principles
- All connections must be encrypted
- Implement proper sandboxing for user workspaces
- Use least privilege access control
- Regular security auditing
- Input validation and sanitization
- Rate limiting and DDoS protection

Please follow Go best practices including proper error handling, clean architecture patterns, and comprehensive testing.
