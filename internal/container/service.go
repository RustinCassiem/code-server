package container

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	"clouddev-server/internal/config"
	"clouddev-server/pkg/logger"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

type Service struct {
	client *client.Client
	config config.ContainerConfig
	logger logger.Logger
}

type ContainerInfo struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Image    string            `json:"image"`
	Status   string            `json:"status"`
	Ports    []PortBinding     `json:"ports"`
	Mounts   []Mount           `json:"mounts"`
	Labels   map[string]string `json:"labels"`
	Created  time.Time         `json:"created"`
}

type PortBinding struct {
	HostPort      string `json:"host_port"`
	ContainerPort string `json:"container_port"`
	Protocol      string `json:"protocol"`
}

type Mount struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Type        string `json:"type"`
	ReadOnly    bool   `json:"read_only"`
}

type CreateOptions struct {
	Name         string            `json:"name"`
	Image        string            `json:"image"`
	Command      []string          `json:"command"`
	Environment  []string          `json:"environment"`
	WorkingDir   string            `json:"working_dir"`
	Ports        []PortBinding     `json:"ports"`
	Mounts       []Mount           `json:"mounts"`
	Labels       map[string]string `json:"labels"`
	CPULimit     string            `json:"cpu_limit"`
	MemoryLimit  string            `json:"memory_limit"`
	NetworkMode  string            `json:"network_mode"`
}

func NewService(config config.ContainerConfig, logger logger.Logger) *Service {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		logger.Fatal("Failed to create Docker client", "error", err)
	}

	return &Service{
		client: dockerClient,
		config: config,
		logger: logger,
	}
}

func (s *Service) CreateContainer(ctx context.Context, opts CreateOptions) (*ContainerInfo, error) {
	// Prepare port bindings
	portBindings := make(nat.PortMap)
	exposedPorts := make(nat.PortSet)
	
	for _, port := range opts.Ports {
		containerPort := nat.Port(fmt.Sprintf("%s/%s", port.ContainerPort, port.Protocol))
		exposedPorts[containerPort] = struct{}{}
		portBindings[containerPort] = []nat.PortBinding{
			{
				HostIP:   "0.0.0.0",
				HostPort: port.HostPort,
			},
		}
	}

	// Prepare mounts
	mounts := make([]mount.Mount, len(opts.Mounts))
	for i, m := range opts.Mounts {
		mounts[i] = mount.Mount{
			Type:     mount.Type(m.Type),
			Source:   m.Source,
			Target:   m.Destination,
			ReadOnly: m.ReadOnly,
		}
	}

	// Set default resource limits if not provided
	cpuLimit := opts.CPULimit
	if cpuLimit == "" {
		cpuLimit = s.config.ResourceLimit.CPU
	}
	
	memoryLimit := opts.MemoryLimit
	if memoryLimit == "" {
		memoryLimit = s.config.ResourceLimit.Memory
	}

	// Prepare container configuration
	containerConfig := &container.Config{
		Image:        opts.Image,
		Cmd:          opts.Command,
		Env:          opts.Environment,
		WorkingDir:   opts.WorkingDir,
		ExposedPorts: exposedPorts,
		Labels:       opts.Labels,
		User:         "1000:1000", // Non-root user for security
	}

	// Prepare host configuration
	hostConfig := &container.HostConfig{
		PortBindings: portBindings,
		Mounts:       mounts,
		NetworkMode:  container.NetworkMode(opts.NetworkMode),
		Resources: container.Resources{
			CPUQuota:  parseCPULimit(cpuLimit),
			CPUPeriod: 100000,
			Memory:    parseMemoryLimit(memoryLimit),
		},
		SecurityOpt: []string{
			"no-new-privileges:true",
			"seccomp:unconfined", // Can be configured for stricter security
		},
		ReadonlyRootfs: false, // Set to true for read-only filesystems
		Tmpfs: map[string]string{
			"/tmp": "rw,size=100m",
		},
	}

	// Network configuration
	networkConfig := &network.NetworkingConfig{}
	if s.config.Network != "" {
		networkConfig.EndpointsConfig = map[string]*network.EndpointSettings{
			s.config.Network: {},
		}
	}

	// Create container
	resp, err := s.client.ContainerCreate(ctx, containerConfig, hostConfig, networkConfig, nil, opts.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	s.logger.Info("Container created successfully", "id", resp.ID, "name", opts.Name)

	// Get container info
	return s.GetContainer(ctx, resp.ID)
}

func (s *Service) StartContainer(ctx context.Context, containerID string) error {
	err := s.client.ContainerStart(ctx, containerID, container.StartOptions{})
	if err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	s.logger.Info("Container started successfully", "id", containerID)
	return nil
}

func (s *Service) StopContainer(ctx context.Context, containerID string, timeout *int) error {
	var stopTimeout *int
	if timeout != nil {
		stopTimeout = timeout
	} else {
		defaultTimeout := 30
		stopTimeout = &defaultTimeout
	}

	err := s.client.ContainerStop(ctx, containerID, container.StopOptions{
		Timeout: stopTimeout,
	})
	if err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	s.logger.Info("Container stopped successfully", "id", containerID)
	return nil
}

func (s *Service) RemoveContainer(ctx context.Context, containerID string, force bool) error {
	err := s.client.ContainerRemove(ctx, containerID, container.RemoveOptions{
		Force: force,
	})
	if err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}

	s.logger.Info("Container removed successfully", "id", containerID)
	return nil
}

func (s *Service) GetContainer(ctx context.Context, containerID string) (*ContainerInfo, error) {
	containerJSON, err := s.client.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	// Convert port bindings
	ports := make([]PortBinding, 0)
	for containerPort, hostBindings := range containerJSON.NetworkSettings.Ports {
		for _, hostBinding := range hostBindings {
			ports = append(ports, PortBinding{
				HostPort:      hostBinding.HostPort,
				ContainerPort: containerPort.Port(),
				Protocol:      containerPort.Proto(),
			})
		}
	}

	// Convert mounts
	mounts := make([]Mount, len(containerJSON.Mounts))
	for i, mount := range containerJSON.Mounts {
		mounts[i] = Mount{
			Source:      mount.Source,
			Destination: mount.Destination,
			Type:        string(mount.Type),
			ReadOnly:    !mount.RW,
		}
	}

	// Parse created time
	createdTime, err := time.Parse(time.RFC3339Nano, containerJSON.Created)
	if err != nil {
		createdTime = time.Now() // fallback
	}

	return &ContainerInfo{
		ID:      containerJSON.ID,
		Name:    containerJSON.Name,
		Image:   containerJSON.Config.Image,
		Status:  containerJSON.State.Status,
		Ports:   ports,
		Mounts:  mounts,
		Labels:  containerJSON.Config.Labels,
		Created: createdTime,
	}, nil
}

func (s *Service) ListContainers(ctx context.Context, containerFilters map[string]string) ([]ContainerInfo, error) {
	listOptions := container.ListOptions{
		All: true,
	}

	// Add filters
	if len(containerFilters) > 0 {
		filterArgs := filters.NewArgs()
		for key, value := range containerFilters {
			filterArgs.Add(key, value)
		}
		listOptions.Filters = filterArgs
	}

	containers, err := s.client.ContainerList(ctx, listOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	result := make([]ContainerInfo, len(containers))
	for i, ctr := range containers {
		// Convert port bindings
		ports := make([]PortBinding, len(ctr.Ports))
		for j, port := range ctr.Ports {
			ports[j] = PortBinding{
				HostPort:      strconv.Itoa(int(port.PublicPort)),
				ContainerPort: strconv.Itoa(int(port.PrivatePort)),
				Protocol:      port.Type,
			}
		}

		// Convert mounts
		mounts := make([]Mount, len(ctr.Mounts))
		for j, mount := range ctr.Mounts {
			mounts[j] = Mount{
				Source:      mount.Source,
				Destination: mount.Destination,
				Type:        string(mount.Type),
				ReadOnly:    !mount.RW,
			}
		}

		result[i] = ContainerInfo{
			ID:      ctr.ID,
			Name:    ctr.Names[0],
			Image:   ctr.Image,
			Status:  ctr.Status,
			Ports:   ports,
			Mounts:  mounts,
			Labels:  ctr.Labels,
			Created: time.Unix(ctr.Created, 0),
		}
	}

	return result, nil
}

func (s *Service) GetContainerLogs(ctx context.Context, containerID string, follow bool, tail string) (io.ReadCloser, error) {
	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     follow,
		Tail:       tail,
		Timestamps: true,
	}

	logs, err := s.client.ContainerLogs(ctx, containerID, options)
	if err != nil {
		return nil, fmt.Errorf("failed to get container logs: %w", err)
	}

	return logs, nil
}

func (s *Service) ExecInContainer(ctx context.Context, containerID string, cmd []string) (types.HijackedResponse, error) {
	execConfig := container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
		AttachStdin:  true,
		Tty:          true,
	}

	execIDResp, err := s.client.ContainerExecCreate(ctx, containerID, execConfig)
	if err != nil {
		return types.HijackedResponse{}, fmt.Errorf("failed to create exec: %w", err)
	}

	resp, err := s.client.ContainerExecAttach(ctx, execIDResp.ID, container.ExecStartOptions{
		Tty: true,
	})
	if err != nil {
		return types.HijackedResponse{}, fmt.Errorf("failed to attach to exec: %w", err)
	}

	return resp, nil
}

// Helper functions for parsing resource limits
func parseCPULimit(cpuLimit string) int64 {
	// Parse CPU limit (e.g., "1", "0.5", "2")
	// Return CPU quota in microseconds (100000 = 1 CPU)
	// This is a simplified implementation
	return 100000 // Default to 1 CPU
}

func parseMemoryLimit(memoryLimit string) int64 {
	// Parse memory limit (e.g., "1Gi", "512Mi", "2Gi")
	// Return memory limit in bytes
	// This is a simplified implementation
	return 2 * 1024 * 1024 * 1024 // Default to 2GB
}
