package main

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"clouddev-server/internal/auth"
	"clouddev-server/internal/config"
	"clouddev-server/internal/container"
	"clouddev-server/internal/git"
	"clouddev-server/internal/ide"
	"clouddev-server/internal/workspace"
	"clouddev-server/pkg/logger"
	"clouddev-server/pkg/security"
	"clouddev-server/pkg/websocket"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	_ "github.com/lib/pq"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		panic("Failed to load configuration: " + err.Error())
	}

	// Initialize logger
	loggerInstance := logger.New(cfg.LogLevel)

	// Initialize database connection
	db, err := sql.Open("postgres", cfg.Database.ConnectionString())
	if err != nil {
		loggerInstance.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Test database connection
	if err := db.Ping(); err != nil {
		loggerInstance.Warn("Database connection test failed", "error", err)
		// Don't exit - allow server to start for development
	}

	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Address(),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	// Test Redis connection
	_, err = redisClient.Ping(context.Background()).Result()
	if err != nil {
		loggerInstance.Warn("Redis connection failed", "error", err)
		// Don't exit - allow server to start for development
	}

	// Initialize services
	authService := auth.NewService(db, redisClient, cfg.Auth)
	containerService := container.NewService(cfg.Container, loggerInstance)
	gitService := git.NewService(cfg.Git)
	workspaceService := workspace.NewService(db, containerService, gitService, cfg.Workspace)
	ideService := ide.NewService(cfg.IDE)

	// Initialize security manager
	securityManager := security.NewManager(cfg.Security)

	// Initialize WebSocket hub
	wsHub := websocket.NewHub(loggerInstance)
	go wsHub.Run()

	// Initialize HTTP handlers and router
	router := setupRouter(cfg, loggerInstance, authService, workspaceService, ideService, wsHub, securityManager)

	// Setup server
	srv := &http.Server{
		Addr:         cfg.ServerAddress(),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	loggerInstance.Info("Starting CloudDev server", "address", cfg.ServerAddress())
	
	// Handle graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			loggerInstance.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	<-c
	loggerInstance.Info("Shutting down server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown server
	if err := srv.Shutdown(ctx); err != nil {
		loggerInstance.Error("Server shutdown failed", "error", err)
		os.Exit(1)
	}

	loggerInstance.Info("Server stopped gracefully")
}

func setupRouter(cfg *config.Config, loggerInstance logger.Logger, authService *auth.Service, 
	workspaceService *workspace.Service, ideService *ide.Service, wsHub *websocket.Hub, 
	securityManager *security.Manager) *gin.Engine {
	
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	
	// Middleware
	router.Use(gin.Recovery())
	router.Use(loggerInstance.GinMiddleware())

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// API routes
	api := router.Group("/api/v1")
	{
		// Authentication routes
		auth := api.Group("/auth")
		{
			auth.POST("/login", authService.Login)
			auth.POST("/logout", authService.Logout)
			auth.POST("/register", authService.Register)
			auth.GET("/me", authService.AuthMiddleware(), authService.GetCurrentUser)
		}

		// Workspace routes
		workspaces := api.Group("/workspaces", authService.AuthMiddleware())
		{
			workspaces.GET("", workspaceService.List)
			workspaces.POST("", workspaceService.Create)
			workspaces.GET("/:id", workspaceService.Get)
			workspaces.PUT("/:id", workspaceService.Update)
			workspaces.DELETE("/:id", workspaceService.Delete)
			workspaces.POST("/:id/start", workspaceService.Start)
			workspaces.POST("/:id/stop", workspaceService.Stop)
			workspaces.GET("/:id/logs", workspaceService.GetLogs)
		}

		// IDE routes
		ide := api.Group("/ide", authService.AuthMiddleware())
		{
			ide.GET("/:workspace_id", ideService.ServeIDE)
			ide.GET("/:workspace_id/files/*path", ideService.GetFile)
			ide.PUT("/:workspace_id/files/*path", ideService.SaveFile)
			ide.DELETE("/:workspace_id/files/*path", ideService.DeleteFile)
			ide.POST("/:workspace_id/terminal", ideService.CreateTerminal)
		}

		// WebSocket routes
		api.GET("/ws/:workspace_id", authService.WSAuthMiddleware(), wsHub.HandleWebSocket)
	}

	// Static files for the web IDE
	router.Static("/static", "./web/static")
	router.StaticFile("/", "./web/index.html")

	return router
}


