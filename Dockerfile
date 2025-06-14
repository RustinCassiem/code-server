# Build stage
FROM golang:1.23.10-alpine3.22 AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o clouddev-server .

# Final stage
FROM alpine:3.19

# Install runtime dependencies and update packages to get latest security fixes
RUN apk update && \
    apk upgrade && \
    apk --no-cache add ca-certificates git docker-cli openssh-client curl

# Create app user
RUN addgroup -g 1001 -S clouddev && \
    adduser -S clouddev -u 1001 -G clouddev

# Create necessary directories
RUN mkdir -p /app/data /app/web /app/logs && \
    chown -R clouddev:clouddev /app

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/clouddev-server .

# Copy static files
COPY --chown=clouddev:clouddev web/ ./web/

# Change to non-root user
USER clouddev

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
CMD ["./clouddev-server"]
