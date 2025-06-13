FROM node:18-alpine

# Install Docker CLI and other dependencies
RUN apk add --no-cache docker-cli git curl bash

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application code
COPY . .

# Create logs directory
RUN mkdir -p logs

# Build TypeScript
RUN npm run build

# Create non-root user
RUN addgroup -g 1001 -S codeserver && \
    adduser -S codeserver -u 1001

# Change ownership of app directory
RUN chown -R codeserver:codeserver /app

# Switch to non-root user
USER codeserver

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start the application
CMD ["node", "dist/server.js"]