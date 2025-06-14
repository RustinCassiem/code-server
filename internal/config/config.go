package config

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
	_ "github.com/lib/pq"
)

type Config struct {
	Environment string `json:"environment"`
	Port        int    `json:"port"`
	LogLevel    string `json:"log_level"`
	
	Database  DatabaseConfig  `json:"database"`
	Redis     RedisConfig     `json:"redis"`
	Auth      AuthConfig      `json:"auth"`
	Security  SecurityConfig  `json:"security"`
	Container ContainerConfig `json:"container"`
	Git       GitConfig       `json:"git"`
	IDE       IDEConfig       `json:"ide"`
	Workspace WorkspaceConfig `json:"workspace"`
}

type DatabaseConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Name     string `json:"name"`
	User     string `json:"user"`
	Password string `json:"password"`
	SSLMode  string `json:"ssl_mode"`
}

type RedisConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	DB       int    `json:"db"`
}

type AuthConfig struct {
	JWTSecret     string        `json:"jwt_secret"`
	TokenExpiry   time.Duration `json:"token_expiry"`
	RefreshExpiry time.Duration `json:"refresh_expiry"`
}

type SecurityConfig struct {
	TLSCertPath    string   `json:"tls_cert_path"`
	TLSKeyPath     string   `json:"tls_key_path"`
	AllowedOrigins []string `json:"allowed_origins"`
	RateLimit      int      `json:"rate_limit"`
	EnableSandbox  bool     `json:"enable_sandbox"`
}

type ContainerConfig struct {
	Runtime       string `json:"runtime"`
	Network       string `json:"network"`
	RegistryURL   string `json:"registry_url"`
	DefaultImage  string `json:"default_image"`
	ResourceLimit struct {
		CPU    string `json:"cpu"`
		Memory string `json:"memory"`
		Disk   string `json:"disk"`
	} `json:"resource_limit"`
}

type GitConfig struct {
	DefaultBranch string `json:"default_branch"`
	SSHKeyPath    string `json:"ssh_key_path"`
}

type IDEConfig struct {
	StaticPath   string `json:"static_path"`
	TemplatePath string `json:"template_path"`
}

type WorkspaceConfig struct {
	DefaultTimeout time.Duration `json:"default_timeout"`
	MaxWorkspaces  int           `json:"max_workspaces"`
	StoragePath    string        `json:"storage_path"`
}

func Load() (*Config, error) {
	cfg := &Config{
		Environment: getEnv("ENVIRONMENT", "development"),
		Port:        getEnvInt("PORT", 8080),
		LogLevel:    getEnv("LOG_LEVEL", "info"),
		
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnvInt("DB_PORT", 5432),
			Name:     getEnv("DB_NAME", "clouddev"),
			User:     getEnv("DB_USER", "postgres"),
			Password: getEnv("DB_PASSWORD", ""),
			SSLMode:  getEnv("DB_SSL_MODE", "disable"),
		},
		
		Redis: RedisConfig{
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     getEnvInt("REDIS_PORT", 6379),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvInt("REDIS_DB", 0),
		},
		
		Auth: AuthConfig{
			JWTSecret:     getEnv("JWT_SECRET", "your-secret-key"),
			TokenExpiry:   time.Hour * 24,
			RefreshExpiry: time.Hour * 24 * 7,
		},
		
		Security: SecurityConfig{
			TLSCertPath:    getEnv("TLS_CERT_PATH", ""),
			TLSKeyPath:     getEnv("TLS_KEY_PATH", ""),
			AllowedOrigins: []string{"*"},
			RateLimit:      getEnvInt("RATE_LIMIT", 100),
			EnableSandbox:  getEnvBool("ENABLE_SANDBOX", true),
		},
		
		Container: ContainerConfig{
			Runtime:      getEnv("CONTAINER_RUNTIME", "docker"),
			Network:      getEnv("CONTAINER_NETWORK", "clouddev"),
			RegistryURL:  getEnv("REGISTRY_URL", ""),
			DefaultImage: getEnv("DEFAULT_IMAGE", "ubuntu:22.04"),
		},
		
		Git: GitConfig{
			DefaultBranch: getEnv("GIT_DEFAULT_BRANCH", "main"),
			SSHKeyPath:    getEnv("GIT_SSH_KEY_PATH", ""),
		},
		
		IDE: IDEConfig{
			StaticPath:   getEnv("IDE_STATIC_PATH", "./web/static"),
			TemplatePath: getEnv("IDE_TEMPLATE_PATH", "./web/templates"),
		},
		
		Workspace: WorkspaceConfig{
			DefaultTimeout: time.Hour * 8,
			MaxWorkspaces:  getEnvInt("MAX_WORKSPACES", 10),
			StoragePath:    getEnv("STORAGE_PATH", "./data"),
		},
	}

	// Set resource limits
	cfg.Container.ResourceLimit.CPU = getEnv("CONTAINER_CPU_LIMIT", "1")
	cfg.Container.ResourceLimit.Memory = getEnv("CONTAINER_MEMORY_LIMIT", "2Gi")
	cfg.Container.ResourceLimit.Disk = getEnv("CONTAINER_DISK_LIMIT", "10Gi")

	return cfg, nil
}

func NewDatabase(cfg DatabaseConfig) (*sql.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name, cfg.SSLMode)
	
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	
	if err := db.Ping(); err != nil {
		return nil, err
	}
	
	return db, nil
}

func NewRedis(cfg RedisConfig) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	
	return client, nil
}

// Helper methods for config

func (d *DatabaseConfig) ConnectionString() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.Name, d.SSLMode)
}

func (r *RedisConfig) Address() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

func (c *Config) ServerAddress() string {
	return fmt.Sprintf(":%d", c.Port)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}
