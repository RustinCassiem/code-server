package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"clouddev-server/internal/config"
)

type Service struct {
	config config.GitConfig
}

type RepositoryInfo struct {
	URL        string   `json:"url"`
	Branch     string   `json:"branch"`
	Commit     string   `json:"commit"`
	Status     string   `json:"status"`
	Modified   []string `json:"modified"`
	Untracked  []string `json:"untracked"`
	Staged     []string `json:"staged"`
}

type CommitInfo struct {
	Hash      string `json:"hash"`
	Author    string `json:"author"`
	Email     string `json:"email"`
	Date      string `json:"date"`
	Message   string `json:"message"`
}

func NewService(config config.GitConfig) *Service {
	return &Service{
		config: config,
	}
}

func (s *Service) CloneRepository(repoURL, targetPath, branch string) error {
	// Ensure target directory exists
	if err := os.MkdirAll(targetPath, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	// Use the specified branch or default
	if branch == "" {
		branch = s.config.DefaultBranch
	}

	// Clone the repository
	cmd := exec.Command("git", "clone", "--branch", branch, "--single-branch", repoURL, targetPath)
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}

	return nil
}

func (s *Service) InitRepository(path string) error {
	cmd := exec.Command("git", "init")
	cmd.Dir = path
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to initialize repository: %w", err)
	}

	// Set default branch if configured
	if s.config.DefaultBranch != "" && s.config.DefaultBranch != "master" {
		cmd = exec.Command("git", "checkout", "-b", s.config.DefaultBranch)
		cmd.Dir = path
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			// Ignore error if branch already exists
		}
	}

	return nil
}

func (s *Service) GetRepositoryInfo(path string) (*RepositoryInfo, error) {
	if !s.IsGitRepository(path) {
		return nil, fmt.Errorf("not a git repository")
	}

	info := &RepositoryInfo{}

	// Get remote URL
	cmd := exec.Command("git", "config", "--get", "remote.origin.url")
	cmd.Dir = path
	if output, err := cmd.Output(); err == nil {
		info.URL = strings.TrimSpace(string(output))
	}

	// Get current branch
	cmd = exec.Command("git", "branch", "--show-current")
	cmd.Dir = path
	if output, err := cmd.Output(); err == nil {
		info.Branch = strings.TrimSpace(string(output))
	}

	// Get current commit
	cmd = exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = path
	if output, err := cmd.Output(); err == nil {
		info.Commit = strings.TrimSpace(string(output))
	}

	// Get repository status
	status, err := s.GetStatus(path)
	if err != nil {
		return nil, err
	}
	
	info.Status = status.Status
	info.Modified = status.Modified
	info.Untracked = status.Untracked
	info.Staged = status.Staged

	return info, nil
}

func (s *Service) GetStatus(path string) (*RepositoryInfo, error) {
	if !s.IsGitRepository(path) {
		return nil, fmt.Errorf("not a git repository")
	}

	info := &RepositoryInfo{}

	// Get porcelain status
	cmd := exec.Command("git", "status", "--porcelain")
	cmd.Dir = path
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get git status: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		status := line[:2]
		file := strings.TrimSpace(line[2:])

		switch {
		case status[0] != ' ' && status[0] != '?':
			// Staged files
			info.Staged = append(info.Staged, file)
		case status[1] != ' ' && status[1] != '?':
			// Modified files
			info.Modified = append(info.Modified, file)
		case status == "??":
			// Untracked files
			info.Untracked = append(info.Untracked, file)
		}
	}

	// Determine overall status
	if len(info.Staged) > 0 {
		info.Status = "staged"
	} else if len(info.Modified) > 0 {
		info.Status = "modified"
	} else if len(info.Untracked) > 0 {
		info.Status = "untracked"
	} else {
		info.Status = "clean"
	}

	return info, nil
}

func (s *Service) AddFiles(path string, files []string) error {
	if !s.IsGitRepository(path) {
		return fmt.Errorf("not a git repository")
	}

	args := append([]string{"add"}, files...)
	cmd := exec.Command("git", args...)
	cmd.Dir = path
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add files: %w", err)
	}

	return nil
}

func (s *Service) Commit(path, message, author, email string) error {
	if !s.IsGitRepository(path) {
		return fmt.Errorf("not a git repository")
	}

	// Set author if provided
	env := os.Environ()
	if author != "" && email != "" {
		env = append(env, fmt.Sprintf("GIT_AUTHOR_NAME=%s", author))
		env = append(env, fmt.Sprintf("GIT_AUTHOR_EMAIL=%s", email))
		env = append(env, fmt.Sprintf("GIT_COMMITTER_NAME=%s", author))
		env = append(env, fmt.Sprintf("GIT_COMMITTER_EMAIL=%s", email))
	}

	cmd := exec.Command("git", "commit", "-m", message)
	cmd.Dir = path
	cmd.Env = env
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to commit: %w", err)
	}

	return nil
}

func (s *Service) Push(path, remote, branch string) error {
	if !s.IsGitRepository(path) {
		return fmt.Errorf("not a git repository")
	}

	if remote == "" {
		remote = "origin"
	}
	
	if branch == "" {
		// Get current branch
		cmd := exec.Command("git", "branch", "--show-current")
		cmd.Dir = path
		if output, err := cmd.Output(); err == nil {
			branch = strings.TrimSpace(string(output))
		} else {
			branch = s.config.DefaultBranch
		}
	}

	cmd := exec.Command("git", "push", remote, branch)
	cmd.Dir = path
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to push: %w", err)
	}

	return nil
}

func (s *Service) Pull(path, remote, branch string) error {
	if !s.IsGitRepository(path) {
		return fmt.Errorf("not a git repository")
	}

	if remote == "" {
		remote = "origin"
	}
	
	if branch == "" {
		// Get current branch
		cmd := exec.Command("git", "branch", "--show-current")
		cmd.Dir = path
		if output, err := cmd.Output(); err == nil {
			branch = strings.TrimSpace(string(output))
		} else {
			branch = s.config.DefaultBranch
		}
	}

	cmd := exec.Command("git", "pull", remote, branch)
	cmd.Dir = path
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to pull: %w", err)
	}

	return nil
}

func (s *Service) CreateBranch(path, branchName string) error {
	if !s.IsGitRepository(path) {
		return fmt.Errorf("not a git repository")
	}

	cmd := exec.Command("git", "checkout", "-b", branchName)
	cmd.Dir = path
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create branch: %w", err)
	}

	return nil
}

func (s *Service) SwitchBranch(path, branchName string) error {
	if !s.IsGitRepository(path) {
		return fmt.Errorf("not a git repository")
	}

	cmd := exec.Command("git", "checkout", branchName)
	cmd.Dir = path
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to switch branch: %w", err)
	}

	return nil
}

func (s *Service) ListBranches(path string) ([]string, error) {
	if !s.IsGitRepository(path) {
		return nil, fmt.Errorf("not a git repository")
	}

	cmd := exec.Command("git", "branch", "-a")
	cmd.Dir = path
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list branches: %w", err)
	}

	var branches []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Remove current branch marker
		if strings.HasPrefix(line, "* ") {
			line = line[2:]
		}
		
		// Skip remote HEAD references
		if strings.Contains(line, "remotes/origin/HEAD") {
			continue
		}
		
		branches = append(branches, line)
	}

	return branches, nil
}

func (s *Service) GetCommitHistory(path string, limit int) ([]CommitInfo, error) {
	if !s.IsGitRepository(path) {
		return nil, fmt.Errorf("not a git repository")
	}

	if limit <= 0 {
		limit = 20
	}

	cmd := exec.Command("git", "log", "--oneline", "--format=%H|%an|%ae|%ad|%s", 
		"--date=iso", fmt.Sprintf("-%d", limit))
	cmd.Dir = path
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get commit history: %w", err)
	}

	var commits []CommitInfo
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) >= 5 {
			commits = append(commits, CommitInfo{
				Hash:    parts[0],
				Author:  parts[1],
				Email:   parts[2],
				Date:    parts[3],
				Message: strings.Join(parts[4:], "|"),
			})
		}
	}

	return commits, nil
}

func (s *Service) IsGitRepository(path string) bool {
	gitDir := filepath.Join(path, ".git")
	if stat, err := os.Stat(gitDir); err == nil {
		return stat.IsDir()
	}
	return false
}

func (s *Service) GetDiff(path string, staged bool) (string, error) {
	if !s.IsGitRepository(path) {
		return "", fmt.Errorf("not a git repository")
	}

	var cmd *exec.Cmd
	if staged {
		cmd = exec.Command("git", "diff", "--cached")
	} else {
		cmd = exec.Command("git", "diff")
	}
	
	cmd.Dir = path
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get diff: %w", err)
	}

	return string(output), nil
}

func (s *Service) ResetFiles(path string, files []string, hard bool) error {
	if !s.IsGitRepository(path) {
		return fmt.Errorf("not a git repository")
	}

	var args []string
	if hard {
		args = append(args, "reset", "--hard")
	} else {
		args = append(args, "checkout", "--")
	}
	args = append(args, files...)

	cmd := exec.Command("git", args...)
	cmd.Dir = path
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reset files: %w", err)
	}

	return nil
}
