package auth

import (
	"context"
	"testing"
	"time"

	"clouddev-server/internal/config"
)

func TestAuthService_GenerateToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret-key-for-jwt-signing",
	}

	service := NewService(cfg, nil, nil, nil)

	token, err := service.GenerateToken("test-user-id")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token == "" {
		t.Fatal("Generated token is empty")
	}

	t.Logf("Generated token: %s", token)
}

func TestAuthService_ValidateToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret-key-for-jwt-signing",
	}

	service := NewService(cfg, nil, nil, nil)

	// Generate a token first
	userID := "test-user-id"
	token, err := service.GenerateToken(userID)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Validate the token
	claims, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, claims.UserID)
	}

	if claims.ExpiresAt.Time.Before(time.Now()) {
		t.Error("Token should not be expired")
	}
}

func TestAuthService_ValidateToken_Invalid(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret-key-for-jwt-signing",
	}

	service := NewService(cfg, nil, nil, nil)

	// Test with invalid token
	_, err := service.ValidateToken("invalid.token.here")
	if err == nil {
		t.Error("Expected error for invalid token, got nil")
	}
}
