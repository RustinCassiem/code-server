package security

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"clouddev-server/internal/config"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type Manager struct {
	config      config.SecurityConfig
	rateLimiters map[string]*rate.Limiter
	mu           sync.RWMutex
}

type RateLimiter struct {
	visitors map[string]*rate.Limiter
	mu       sync.RWMutex
}

func NewManager(config config.SecurityConfig) *Manager {
	return &Manager{
		config:       config,
		rateLimiters: make(map[string]*rate.Limiter),
	}
}

// SecurityHeaders middleware adds security headers to all responses
func (m *Manager) SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent XSS attacks
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		
		// HSTS header for HTTPS
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		
		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")
		
		// Referrer policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		
		// Feature policy / Permissions policy
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		
		// Content Security Policy
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data: https:; " +
			"connect-src 'self' ws: wss:; " +
			"font-src 'self'; " +
			"frame-ancestors 'none'"
		c.Header("Content-Security-Policy", csp)
		
		c.Next()
	}
}

// CORS middleware handles Cross-Origin Resource Sharing
func (m *Manager) CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range m.config.AllowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}
		
		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
		}
		
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-Requested-With")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")
		
		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		
		c.Next()
	}
}

// RateLimiter middleware implements rate limiting per IP
func (m *Manager) RateLimiter() gin.HandlerFunc {
	limiter := NewRateLimiter(rate.Limit(m.config.RateLimit), m.config.RateLimit*2)
	
	return func(c *gin.Context) {
		ip := m.getClientIP(c)
		
		if !limiter.Allow(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "Rate limit exceeded",
				"message": "Too many requests from this IP",
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// InputValidation middleware validates and sanitizes input
func (m *Manager) InputValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Validate content length
		if c.Request.ContentLength > 10*1024*1024 { // 10MB limit
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "Request entity too large",
			})
			c.Abort()
			return
		}
		
		// Validate Content-Type for POST/PUT requests
		if c.Request.Method == "POST" || c.Request.Method == "PUT" {
			contentType := c.GetHeader("Content-Type")
			if contentType != "" && !isValidContentType(contentType) {
				c.JSON(http.StatusUnsupportedMediaType, gin.H{
					"error": "Unsupported media type",
				})
				c.Abort()
				return
			}
		}
		
		c.Next()
	}
}

// AuthenticationBypass middleware checks for authentication bypass attempts
func (m *Manager) AuthenticationBypass() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for common authentication bypass patterns
		userAgent := c.GetHeader("User-Agent")
		if strings.Contains(strings.ToLower(userAgent), "sqlmap") ||
			strings.Contains(strings.ToLower(userAgent), "nikto") ||
			strings.Contains(strings.ToLower(userAgent), "burp") {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Suspicious activity detected",
			})
			c.Abort()
			return
		}
		
		// Check for SQL injection patterns in headers
		for _, values := range c.Request.Header {
			for _, value := range values {
				if containsSQLInjection(value) {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "Invalid input detected",
					})
					c.Abort()
					return
				}
			}
		}
		
		c.Next()
	}
}

// SandboxValidation middleware validates workspace sandbox constraints
func (m *Manager) SandboxValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !m.config.EnableSandbox {
			c.Next()
			return
		}
		
		// Validate workspace access patterns
		workspaceID := c.Param("workspace_id")
		if workspaceID != "" {
			if !isValidWorkspaceID(workspaceID) {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Invalid workspace ID",
				})
				c.Abort()
				return
			}
		}
		
		// Validate file paths for directory traversal
		filePath := c.Param("path")
		if filePath != "" && containsDirectoryTraversal(filePath) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied: invalid path",
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	return &RateLimiter{
		visitors: make(map[string]*rate.Limiter),
	}
}

// Allow checks if a request from an IP is allowed
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	limiter, exists := rl.visitors[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Every(time.Minute), 100) // 100 requests per minute
		rl.visitors[ip] = limiter
	}
	rl.mu.Unlock()
	
	return limiter.Allow()
}

// CleanupRateLimiters removes old rate limiters
func (rl *RateLimiter) CleanupRateLimiters() {
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		
		for range ticker.C {
			rl.mu.Lock()
			// Clear all limiters every hour to prevent memory leaks
			rl.visitors = make(map[string]*rate.Limiter)
			rl.mu.Unlock()
		}
	}()
}

// getClientIP extracts the real client IP from various headers
func (m *Manager) getClientIP(c *gin.Context) string {
	// Check X-Forwarded-For header
	xForwardedFor := c.GetHeader("X-Forwarded-For")
	if xForwardedFor != "" {
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	// Check X-Real-IP header
	xRealIP := c.GetHeader("X-Real-IP")
	if xRealIP != "" {
		return xRealIP
	}
	
	// Fall back to RemoteAddr
	return c.ClientIP()
}

// isValidContentType checks if the content type is allowed
func isValidContentType(contentType string) bool {
	allowedTypes := []string{
		"application/json",
		"application/x-www-form-urlencoded",
		"multipart/form-data",
		"text/plain",
	}
	
	for _, allowed := range allowedTypes {
		if strings.HasPrefix(contentType, allowed) {
			return true
		}
	}
	
	return false
}

// containsSQLInjection checks for common SQL injection patterns
func containsSQLInjection(input string) bool {
	input = strings.ToLower(input)
	patterns := []string{
		"union select",
		"' or '1'='1",
		"' or 1=1",
		"' or 'a'='a",
		"'; drop table",
		"'; delete from",
		"<script",
		"javascript:",
		"eval(",
		"expression(",
	}
	
	for _, pattern := range patterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}
	
	return false
}

// containsDirectoryTraversal checks for directory traversal patterns
func containsDirectoryTraversal(path string) bool {
	// Check for common directory traversal patterns
	patterns := []string{
		"../",
		"..\\",
		"....//",
		"....\\\\",
		"%2e%2e%2f",
		"%2e%2e%5c",
		"..%2f",
		"..%5c",
	}
	
	path = strings.ToLower(path)
	for _, pattern := range patterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	
	return false
}

// isValidWorkspaceID validates workspace ID format
func isValidWorkspaceID(workspaceID string) bool {
	// Workspace ID should only contain alphanumeric characters, hyphens, and underscores
	if len(workspaceID) == 0 || len(workspaceID) > 100 {
		return false
	}
	
	for _, char := range workspaceID {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_') {
			return false
		}
	}
	
	return true
}

// LogSecurityEvent logs security-related events
func (m *Manager) LogSecurityEvent(eventType, message, clientIP string) {
	// TODO: Implement proper security logging
	// This could send logs to a SIEM system, log aggregation service, etc.
	timestamp := time.Now().Format(time.RFC3339)
	logEntry := map[string]interface{}{
		"timestamp":  timestamp,
		"event_type": eventType,
		"message":    message,
		"client_ip":  clientIP,
		"severity":   "warning",
	}
	
	// For now, just print to stdout
	// In production, this should be sent to a proper logging system
	_ = logEntry
}

// RequestSizeLimit middleware limits request size
func (m *Manager) RequestSizeLimit(maxSize int64) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		if c.Request.ContentLength > maxSize {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "Request entity too large",
			})
			c.Abort()
			return
		}
		c.Next()
	})
}

// IPWhitelist middleware allows only whitelisted IPs (for admin endpoints)
func (m *Manager) IPWhitelist(allowedIPs []string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		clientIP := m.getClientIP(c)
		
		allowed := false
		for _, allowedIP := range allowedIPs {
			if allowedIP == clientIP {
				allowed = true
				break
			}
		}
		
		if !allowed {
			m.LogSecurityEvent("ip_blocked", "Unauthorized IP access attempt", clientIP)
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied",
			})
			c.Abort()
			return
		}
		
		c.Next()
	})
}
