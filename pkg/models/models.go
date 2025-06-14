package models

import (
	"time"
)

type User struct {
	ID        string    `json:"id" db:"id"`
	Email     string    `json:"email" db:"email"`
	Name      string    `json:"name" db:"name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type Workspace struct {
	ID          string    `json:"id" db:"id"`
	UserID      string    `json:"user_id" db:"user_id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	Status      string    `json:"status" db:"status"` // created, running, stopped, error
	Image       string    `json:"image" db:"image"`
	GitURL      string    `json:"git_url" db:"git_url"`
	GitBranch   string    `json:"git_branch" db:"git_branch"`
	ContainerID string    `json:"container_id,omitempty" db:"container_id"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

type Session struct {
	ID          string    `json:"id" db:"id"`
	UserID      string    `json:"user_id" db:"user_id"`
	WorkspaceID string    `json:"workspace_id" db:"workspace_id"`
	Token       string    `json:"token" db:"token"`
	ExpiresAt   time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type File struct {
	ID          string    `json:"id" db:"id"`
	WorkspaceID string    `json:"workspace_id" db:"workspace_id"`
	Path        string    `json:"path" db:"path"`
	Content     string    `json:"content" db:"content"`
	Size        int64     `json:"size" db:"size"`
	MimeType    string    `json:"mime_type" db:"mime_type"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

type Terminal struct {
	ID          string    `json:"id" db:"id"`
	WorkspaceID string    `json:"workspace_id" db:"workspace_id"`
	UserID      string    `json:"user_id" db:"user_id"`
	SessionID   string    `json:"session_id" db:"session_id"`
	Command     string    `json:"command" db:"command"`
	Args        []string  `json:"args" db:"args"`
	Status      string    `json:"status" db:"status"` // active, closed
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

type Collaboration struct {
	ID          string    `json:"id" db:"id"`
	WorkspaceID string    `json:"workspace_id" db:"workspace_id"`
	UserID      string    `json:"user_id" db:"user_id"`
	FilePath    string    `json:"file_path" db:"file_path"`
	Operation   string    `json:"operation" db:"operation"` // edit, create, delete
	Changes     string    `json:"changes" db:"changes"`     // JSON encoded changes
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type SecurityEvent struct {
	ID          string    `json:"id" db:"id"`
	UserID      string    `json:"user_id,omitempty" db:"user_id"`
	WorkspaceID string    `json:"workspace_id,omitempty" db:"workspace_id"`
	EventType   string    `json:"event_type" db:"event_type"`
	Severity    string    `json:"severity" db:"severity"` // low, medium, high, critical
	Message     string    `json:"message" db:"message"`
	ClientIP    string    `json:"client_ip" db:"client_ip"`
	UserAgent   string    `json:"user_agent" db:"user_agent"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// Authentication request/response models
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
}

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
	Name     string `json:"name" validate:"required,min=2"`
}

type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}
