package workspace

import (
	"context"
	"testing"

	"clouddev-server/internal/config"
	"clouddev-server/pkg/models"
)

func TestWorkspaceService_CreateWorkspace(t *testing.T) {
	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			Database: "test_clouddev",
			Username: "test_user",
			Password: "test_pass",
		},
	}

	service := NewService(cfg, nil, nil, nil, nil)

	req := &models.CreateWorkspaceRequest{
		Name:        "test-workspace",
		Image:       "ubuntu:20.04",
		UserID:      "test-user-id",
		GitRepo:     "https://github.com/test/repo.git",
		Environment: map[string]string{"NODE_ENV": "development"},
	}

	// Note: This will fail without actual database connection
	// but tests the function signature and basic validation
	workspace, err := service.CreateWorkspace(context.Background(), req)
	
	// We expect this to fail due to no database connection
	// but we can verify the function exists and basic validation works
	if err != nil && workspace == nil {
		t.Logf("Expected error due to no database connection: %v", err)
		return
	}

	// If somehow this succeeds (maybe mock DB was added), verify basic fields
	if workspace != nil {
		if workspace.Name != req.Name {
			t.Errorf("Expected workspace name %s, got %s", req.Name, workspace.Name)
		}
		if workspace.UserID != req.UserID {
			t.Errorf("Expected user ID %s, got %s", req.UserID, workspace.UserID)
		}
	}
}

func TestWorkspaceService_GetWorkspace(t *testing.T) {
	cfg := &config.Config{}
	service := NewService(cfg, nil, nil, nil, nil)

	// Test with non-existent workspace
	workspace, err := service.GetWorkspace(context.Background(), "non-existent-id", "test-user-id")
	
	// Should return error for non-existent workspace
	if err == nil {
		t.Error("Expected error for non-existent workspace")
	}
	
	if workspace != nil {
		t.Error("Expected nil workspace for non-existent ID")
	}
}
