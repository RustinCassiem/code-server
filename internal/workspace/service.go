package workspace

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"clouddev-server/internal/config"
	"clouddev-server/internal/container"
	"clouddev-server/internal/git"
	"clouddev-server/pkg/models"

	"github.com/gin-gonic/gin"
)

type Service struct {
	db               *sql.DB
	containerService *container.Service
	gitService       *git.Service
	config           config.WorkspaceConfig
}

type CreateWorkspaceRequest struct {
	Name        string            `json:"name" binding:"required"`
	Description string            `json:"description"`
	Image       string            `json:"image"`
	GitURL      string            `json:"git_url"`
	GitBranch   string            `json:"git_branch"`
	Environment []string          `json:"environment"`
	Labels      map[string]string `json:"labels"`
}

type UpdateWorkspaceRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Environment []string          `json:"environment"`
	Labels      map[string]string `json:"labels"`
}

func NewService(db *sql.DB, containerService *container.Service, gitService *git.Service, config config.WorkspaceConfig) *Service {
	return &Service{
		db:               db,
		containerService: containerService,
		gitService:       gitService,
		config:           config,
	}
}

func (s *Service) List(c *gin.Context) {
	userID := c.GetString("user_id")
	
	// Parse query parameters
	limit := 10
	offset := 0
	
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	// Get workspaces from database
	rows, err := s.db.Query(`
		SELECT id, name, description, status, image, git_url, git_branch, 
		       container_id, created_at, updated_at
		FROM workspaces 
		WHERE user_id = $1 
		ORDER BY updated_at DESC 
		LIMIT $2 OFFSET $3
	`, userID, limit, offset)
	
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch workspaces"})
		return
	}
	defer rows.Close()

	var workspaces []models.Workspace
	for rows.Next() {
		var ws models.Workspace
		var containerID sql.NullString
		
		err := rows.Scan(&ws.ID, &ws.Name, &ws.Description, &ws.Status, 
			&ws.Image, &ws.GitURL, &ws.GitBranch, &containerID, 
			&ws.CreatedAt, &ws.UpdatedAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan workspace"})
			return
		}
		
		ws.UserID = userID
		if containerID.Valid {
			ws.ContainerID = containerID.String
		}
		
		workspaces = append(workspaces, ws)
	}

	// Get total count
	var total int
	err = s.db.QueryRow("SELECT COUNT(*) FROM workspaces WHERE user_id = $1", userID).Scan(&total)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get total count"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"workspaces": workspaces,
		"total":      total,
		"limit":      limit,
		"offset":     offset,
	})
}

func (s *Service) Create(c *gin.Context) {
	userID := c.GetString("user_id")
	
	var req CreateWorkspaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check workspace limit
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM workspaces WHERE user_id = $1", userID).Scan(&count)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check workspace limit"})
		return
	}
	
	if count >= s.config.MaxWorkspaces {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Maximum number of workspaces reached"})
		return
	}

	// Generate workspace ID
	workspaceID, err := generateWorkspaceID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate workspace ID"})
		return
	}

	// Set default image if not provided
	image := req.Image
	if image == "" {
		image = "clouddev/workspace:latest" // Default workspace image
	}

	// Set default git branch if not provided
	gitBranch := req.GitBranch
	if gitBranch == "" {
		gitBranch = "main"
	}

	// Create workspace in database
	workspace := &models.Workspace{
		ID:          workspaceID,
		UserID:      userID,
		Name:        req.Name,
		Description: req.Description,
		Status:      "created",
		Image:       image,
		GitURL:      req.GitURL,
		GitBranch:   gitBranch,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	_, err = s.db.Exec(`
		INSERT INTO workspaces (id, user_id, name, description, status, image, 
		                       git_url, git_branch, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, workspace.ID, workspace.UserID, workspace.Name, workspace.Description,
		workspace.Status, workspace.Image, workspace.GitURL, workspace.GitBranch,
		workspace.CreatedAt, workspace.UpdatedAt)
	
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create workspace"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"workspace": workspace})
}

func (s *Service) Get(c *gin.Context) {
	userID := c.GetString("user_id")
	workspaceID := c.Param("id")

	var workspace models.Workspace
	var containerID sql.NullString
	
	err := s.db.QueryRow(`
		SELECT id, name, description, status, image, git_url, git_branch, 
		       container_id, created_at, updated_at
		FROM workspaces 
		WHERE id = $1 AND user_id = $2
	`, workspaceID, userID).Scan(&workspace.ID, &workspace.Name, &workspace.Description,
		&workspace.Status, &workspace.Image, &workspace.GitURL, &workspace.GitBranch,
		&containerID, &workspace.CreatedAt, &workspace.UpdatedAt)
	
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Workspace not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch workspace"})
		return
	}

	workspace.UserID = userID
	if containerID.Valid {
		workspace.ContainerID = containerID.String
	}

	c.JSON(http.StatusOK, gin.H{"workspace": workspace})
}

func (s *Service) Update(c *gin.Context) {
	userID := c.GetString("user_id")
	workspaceID := c.Param("id")

	var req UpdateWorkspaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if workspace exists and belongs to user
	var exists bool
	err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM workspaces WHERE id = $1 AND user_id = $2)", workspaceID, userID).Scan(&exists)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check workspace"})
		return
	}
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Workspace not found"})
		return
	}

	// Update workspace
	_, err = s.db.Exec(`
		UPDATE workspaces 
		SET name = $1, description = $2, updated_at = $3
		WHERE id = $4 AND user_id = $5
	`, req.Name, req.Description, time.Now(), workspaceID, userID)
	
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update workspace"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Workspace updated successfully"})
}

func (s *Service) Delete(c *gin.Context) {
	userID := c.GetString("user_id")
	workspaceID := c.Param("id")

	// Get workspace with container info
	var containerID sql.NullString
	var status string
	err := s.db.QueryRow(`
		SELECT container_id, status FROM workspaces 
		WHERE id = $1 AND user_id = $2
	`, workspaceID, userID).Scan(&containerID, &status)
	
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Workspace not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch workspace"})
		return
	}

	// Stop and remove container if it exists
	if containerID.Valid && status == "running" {
		ctx := context.Background()
		if err := s.containerService.StopContainer(ctx, containerID.String, nil); err != nil {
			// Log error but continue with deletion
			c.Header("X-Warning", "Failed to stop container")
		}
		if err := s.containerService.RemoveContainer(ctx, containerID.String, true); err != nil {
			// Log error but continue with deletion
			c.Header("X-Warning", "Failed to remove container")
		}
	}

	// Delete workspace from database
	_, err = s.db.Exec("DELETE FROM workspaces WHERE id = $1 AND user_id = $2", workspaceID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete workspace"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Workspace deleted successfully"})
}

func (s *Service) Start(c *gin.Context) {
	userID := c.GetString("user_id")
	workspaceID := c.Param("id")

	// Get workspace
	var workspace models.Workspace
	var containerID sql.NullString
	
	err := s.db.QueryRow(`
		SELECT id, name, status, image, git_url, git_branch, container_id
		FROM workspaces 
		WHERE id = $1 AND user_id = $2
	`, workspaceID, userID).Scan(&workspace.ID, &workspace.Name, &workspace.Status,
		&workspace.Image, &workspace.GitURL, &workspace.GitBranch, &containerID)
	
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Workspace not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch workspace"})
		return
	}

	workspace.UserID = userID
	if containerID.Valid {
		workspace.ContainerID = containerID.String
	}

	if workspace.Status == "running" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Workspace is already running"})
		return
	}

	ctx := context.Background()

	// Create container if it doesn't exist
	if workspace.ContainerID == "" {
		containerOpts := container.CreateOptions{
			Name:        fmt.Sprintf("workspace-%s", workspace.ID),
			Image:       workspace.Image,
			WorkingDir:  "/workspace",
			Environment: []string{
				"WORKSPACE_ID=" + workspace.ID,
				"USER_ID=" + userID,
			},
			Labels: map[string]string{
				"clouddev.workspace.id":      workspace.ID,
				"clouddev.workspace.user_id": userID,
				"clouddev.workspace.name":    workspace.Name,
			},
			Mounts: []container.Mount{
				{
					Source:      filepath.Join(s.config.StoragePath, "workspaces", workspace.ID),
					Destination: "/workspace",
					Type:        "bind",
					ReadOnly:    false,
				},
			},
			Ports: []container.PortBinding{
				{
					HostPort:      "0", // Auto-assign port
					ContainerPort: "8080",
					Protocol:      "tcp",
				},
			},
		}

		containerInfo, err := s.containerService.CreateContainer(ctx, containerOpts)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create container"})
			return
		}

		workspace.ContainerID = containerInfo.ID

		// Update workspace with container ID
		_, err = s.db.Exec(`
			UPDATE workspaces SET container_id = $1, updated_at = $2 
			WHERE id = $3
		`, workspace.ContainerID, time.Now(), workspace.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update workspace"})
			return
		}
	}

	// Start container
	err = s.containerService.StartContainer(ctx, workspace.ContainerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start container"})
		return
	}

	// Update workspace status
	_, err = s.db.Exec(`
		UPDATE workspaces SET status = 'running', updated_at = $1 
		WHERE id = $2
	`, time.Now(), workspace.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update workspace status"})
		return
	}

	// Clone git repository if specified and not already cloned
	if workspace.GitURL != "" {
		go func() {
			workspacePath := filepath.Join(s.config.StoragePath, "workspaces", workspace.ID)
			if err := s.gitService.CloneRepository(workspace.GitURL, workspacePath, workspace.GitBranch); err != nil {
				// Log error but don't fail the workspace start
				fmt.Printf("Failed to clone repository: %v\n", err)
			}
		}()
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "Workspace started successfully",
		"workspace_id": workspace.ID,
		"container_id": workspace.ContainerID,
	})
}

func (s *Service) Stop(c *gin.Context) {
	userID := c.GetString("user_id")
	workspaceID := c.Param("id")

	// Get workspace
	var workspace models.Workspace
	var containerID sql.NullString
	
	err := s.db.QueryRow(`
		SELECT id, status, container_id FROM workspaces 
		WHERE id = $1 AND user_id = $2
	`, workspaceID, userID).Scan(&workspace.ID, &workspace.Status, &containerID)
	
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Workspace not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch workspace"})
		return
	}

	if containerID.Valid {
		workspace.ContainerID = containerID.String
	}

	if workspace.Status == "stopped" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Workspace is already stopped"})
		return
	}

	// Stop container if it exists
	if workspace.ContainerID != "" {
		ctx := context.Background()
		err = s.containerService.StopContainer(ctx, workspace.ContainerID, nil)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to stop container"})
			return
		}
	}

	// Update workspace status
	_, err = s.db.Exec(`
		UPDATE workspaces SET status = 'stopped', updated_at = $1 
		WHERE id = $2
	`, time.Now(), workspace.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update workspace status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Workspace stopped successfully"})
}

func (s *Service) GetLogs(c *gin.Context) {
	userID := c.GetString("user_id")
	workspaceID := c.Param("id")

	// Get workspace container ID
	var containerID sql.NullString
	err := s.db.QueryRow(`
		SELECT container_id FROM workspaces 
		WHERE id = $1 AND user_id = $2
	`, workspaceID, userID).Scan(&containerID)
	
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Workspace not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch workspace"})
		return
	}

	if !containerID.Valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Workspace has no container"})
		return
	}

	// Get query parameters
	follow := c.Query("follow") == "true"
	tail := c.DefaultQuery("tail", "100")

	ctx := context.Background()
	logs, err := s.containerService.GetContainerLogs(ctx, containerID.String, follow, tail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get container logs"})
		return
	}
	defer logs.Close()

	// Stream logs to client
	c.Stream(func(w io.Writer) bool {
		buffer := make([]byte, 1024)
		n, err := logs.Read(buffer)
		if err != nil {
			return false
		}
		w.Write(buffer[:n])
		return true
	})
}

func generateWorkspaceID() (string, error) {
	// Generate a unique workspace ID
	return fmt.Sprintf("ws-%d", time.Now().UnixNano()), nil
}
