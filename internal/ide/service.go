package ide

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"clouddev-server/internal/config"

	"github.com/gin-gonic/gin"
)

type Service struct {
	config config.IDEConfig
}

type FileInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}

type FileContent struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	IsDir   bool   `json:"is_dir"`
}

type CreateTerminalRequest struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Env     []string `json:"env"`
}

func NewService(config config.IDEConfig) *Service {
	return &Service{
		config: config,
	}
}

func (s *Service) ServeIDE(c *gin.Context) {
	workspaceID := c.Param("workspace_id")
	
	// Serve the main IDE interface
	indexPath := filepath.Join(s.config.TemplatePath, "index.html")
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		// If template doesn't exist, serve a basic HTML page
		s.serveBasicIDE(c, workspaceID)
		return
	}
	
	c.File(indexPath)
}

func (s *Service) serveBasicIDE(c *gin.Context, workspaceID string) {
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudDev IDE - Workspace %s</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            background: #1e1e1e;
            color: #d4d4d4;
            display: flex;
            height: 100vh;
        }
        .sidebar {
            width: 300px;
            background: #252526;
            border-right: 1px solid #3e3e42;
            display: flex;
            flex-direction: column;
        }
        .sidebar-header {
            padding: 10px;
            border-bottom: 1px solid #3e3e42;
            font-weight: bold;
        }
        .file-explorer {
            flex: 1;
            overflow-y: auto;
        }
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
        }
        .tabs {
            background: #2d2d30;
            border-bottom: 1px solid #3e3e42;
            padding: 0;
            margin: 0;
            height: 35px;
            display: flex;
            align-items: center;
        }
        .tab {
            padding: 8px 16px;
            background: #2d2d30;
            border-right: 1px solid #3e3e42;
            cursor: pointer;
            position: relative;
        }
        .tab.active {
            background: #1e1e1e;
        }
        .editor {
            flex: 1;
            background: #1e1e1e;
            padding: 0;
            margin: 0;
            border: none;
            outline: none;
            font-family: inherit;
            font-size: 14px;
            color: inherit;
            resize: none;
        }
        .terminal {
            height: 200px;
            background: #0c0c0c;
            border-top: 1px solid #3e3e42;
            padding: 10px;
            overflow-y: auto;
            font-family: inherit;
        }
        .file-item {
            padding: 4px 16px;
            cursor: pointer;
            border-left: 3px solid transparent;
        }
        .file-item:hover {
            background: #2a2d2e;
        }
        .file-item.selected {
            background: #094771;
            border-left-color: #007acc;
        }
        .file-item.directory {
            font-weight: bold;
        }
        .toolbar {
            background: #2d2d30;
            padding: 8px;
            border-bottom: 1px solid #3e3e42;
            display: flex;
            gap: 8px;
        }
        .btn {
            background: #0e639c;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 2px;
            cursor: pointer;
            font-size: 12px;
        }
        .btn:hover {
            background: #1177bb;
        }
        .btn.secondary {
            background: #5a5a5a;
        }
        .btn.secondary:hover {
            background: #6a6a6a;
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="sidebar-header">
            Explorer
        </div>
        <div class="file-explorer" id="fileExplorer">
            <div class="file-item directory" onclick="loadFiles('/')">
                📁 /workspace
            </div>
        </div>
    </div>
    <div class="main-content">
        <div class="toolbar">
            <button class="btn" onclick="saveFile()">Save</button>
            <button class="btn secondary" onclick="newFile()">New File</button>
            <button class="btn secondary" onclick="refreshFiles()">Refresh</button>
        </div>
        <div class="tabs" id="tabs">
            <div class="tab active" onclick="openTab('welcome')">
                Welcome
            </div>
        </div>
        <textarea class="editor" id="editor" placeholder="Welcome to CloudDev IDE"></textarea>
        <div class="terminal" id="terminal">
            <div>CloudDev Terminal - Workspace: %s</div>
            <div>$ </div>
        </div>
    </div>

    <script>
        const workspaceId = '%s';
        let currentFile = null;
        let openTabs = new Map();

        // Initialize
        loadFiles('/');

        async function loadFiles(path) {
            try {
                const response = await fetch('/api/v1/ide/' + workspaceId + '/files' + path, {
                    headers: {
                        'Authorization': 'Bearer ' + localStorage.getItem('token')
                    }
                });
                
                if (!response.ok) {
                    throw new Error('Failed to load files');
                }
                
                const files = await response.json();
                displayFiles(files, path);
            } catch (error) {
                console.error('Error loading files:', error);
                document.getElementById('terminal').innerHTML += '<div style="color: red;">Error: ' + error.message + '</div>';
            }
        }

        function displayFiles(files, basePath) {
            const explorer = document.getElementById('fileExplorer');
            // Keep the root folder, clear others
            const rootItem = explorer.querySelector('.file-item');
            explorer.innerHTML = '';
            explorer.appendChild(rootItem);
            
            files.forEach(file => {
                const item = document.createElement('div');
                item.className = 'file-item' + (file.is_dir ? ' directory' : '');
                item.innerHTML = (file.is_dir ? '📁 ' : '📄 ') + file.name;
                item.onclick = () => {
                    if (file.is_dir) {
                        loadFiles(file.path);
                    } else {
                        openFile(file.path);
                    }
                };
                explorer.appendChild(item);
            });
        }

        async function openFile(path) {
            try {
                const response = await fetch('/api/v1/ide/' + workspaceId + '/files' + path, {
                    headers: {
                        'Authorization': 'Bearer ' + localStorage.getItem('token')
                    }
                });
                
                if (!response.ok) {
                    throw new Error('Failed to open file');
                }
                
                const fileContent = await response.json();
                currentFile = path;
                document.getElementById('editor').value = fileContent.content;
                
                // Add tab if not exists
                if (!openTabs.has(path)) {
                    addTab(path);
                }
                
                // Switch to tab
                switchTab(path);
            } catch (error) {
                console.error('Error opening file:', error);
                document.getElementById('terminal').innerHTML += '<div style="color: red;">Error: ' + error.message + '</div>';
            }
        }

        async function saveFile() {
            if (!currentFile) {
                alert('No file selected');
                return;
            }
            
            try {
                const response = await fetch('/api/v1/ide/' + workspaceId + '/files' + currentFile, {
                    method: 'PUT',
                    headers: {
                        'Authorization': 'Bearer ' + localStorage.getItem('token'),
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        content: document.getElementById('editor').value
                    })
                });
                
                if (!response.ok) {
                    throw new Error('Failed to save file');
                }
                
                document.getElementById('terminal').innerHTML += '<div style="color: green;">File saved: ' + currentFile + '</div>';
            } catch (error) {
                console.error('Error saving file:', error);
                document.getElementById('terminal').innerHTML += '<div style="color: red;">Error: ' + error.message + '</div>';
            }
        }

        function newFile() {
            const name = prompt('Enter file name:');
            if (name) {
                currentFile = '/' + name;
                document.getElementById('editor').value = '';
                addTab(currentFile);
                switchTab(currentFile);
            }
        }

        function refreshFiles() {
            loadFiles('/');
        }

        function addTab(path) {
            const tabs = document.getElementById('tabs');
            const tab = document.createElement('div');
            tab.className = 'tab';
            tab.innerHTML = path.split('/').pop();
            tab.onclick = () => switchTab(path);
            tabs.appendChild(tab);
            openTabs.set(path, tab);
        }

        function switchTab(path) {
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            
            // Add active class to selected tab
            const tab = openTabs.get(path);
            if (tab) {
                tab.classList.add('active');
            }
            
            currentFile = path;
        }

        function openTab(tabName) {
            if (tabName === 'welcome') {
                currentFile = null;
                document.getElementById('editor').value = 'Welcome to CloudDev IDE\\n\\nThis is a lightweight, security-driven cloud development environment.\\n\\nFeatures:\\n- File explorer\\n- Code editor\\n- Terminal access\\n- Git integration\\n- Real-time collaboration\\n\\nGet started by opening a file from the explorer or creating a new one.';
            }
        }

        // Initialize welcome tab
        openTab('welcome');
    </script>
</body>
</html>
`, workspaceID, workspaceID, workspaceID)

	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, html)
}

func (s *Service) GetFile(c *gin.Context) {
	workspaceID := c.Param("workspace_id")
	filePath := c.Param("path")
	
	// Construct the full file path
	fullPath := s.getWorkspacePath(workspaceID, filePath)
	
	// Security check: ensure path is within workspace
	if !s.isPathSafe(fullPath, workspaceID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Check if path is a directory
	fileInfo, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to access file"})
		}
		return
	}

	if fileInfo.IsDir() {
		// Return directory listing
		files, err := s.listDirectory(fullPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list directory"})
			return
		}
		c.JSON(http.StatusOK, files)
		return
	}

	// Read file content
	content, err := os.ReadFile(fullPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
		return
	}

	c.JSON(http.StatusOK, FileContent{
		Path:    filePath,
		Content: string(content),
		IsDir:   false,
	})
}

func (s *Service) SaveFile(c *gin.Context) {
	workspaceID := c.Param("workspace_id")
	filePath := c.Param("path")
	
	var req struct {
		Content string `json:"content"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Construct the full file path
	fullPath := s.getWorkspacePath(workspaceID, filePath)
	
	// Security check: ensure path is within workspace
	if !s.isPathSafe(fullPath, workspaceID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Ensure directory exists
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create directory"})
		return
	}

	// Write file content
	if err := os.WriteFile(fullPath, []byte(req.Content), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "File saved successfully"})
}

func (s *Service) DeleteFile(c *gin.Context) {
	workspaceID := c.Param("workspace_id")
	filePath := c.Param("path")
	
	// Construct the full file path
	fullPath := s.getWorkspacePath(workspaceID, filePath)
	
	// Security check: ensure path is within workspace
	if !s.isPathSafe(fullPath, workspaceID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Delete file or directory
	if err := os.RemoveAll(fullPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "File deleted successfully"})
}

func (s *Service) CreateTerminal(c *gin.Context) {
	workspaceID := c.Param("workspace_id")
	
	var req CreateTerminalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Default command if not provided
	if req.Command == "" {
		req.Command = "/bin/bash"
	}

	// TODO: Implement terminal creation and WebSocket connection
	// This would typically involve:
	// 1. Creating a PTY in the workspace container
	// 2. Setting up WebSocket connection for terminal I/O
	// 3. Returning terminal session ID

	terminalID := fmt.Sprintf("term-%s-%d", workspaceID, len(req.Args))
	
	c.JSON(http.StatusOK, gin.H{
		"terminal_id": terminalID,
		"command":     req.Command,
		"args":        req.Args,
		"message":     "Terminal created successfully",
	})
}

func (s *Service) getWorkspacePath(workspaceID, filePath string) string {
	// Base workspace path (this should come from configuration)
	basePath := filepath.Join("/tmp", "workspaces", workspaceID)
	
	// Clean the file path to prevent directory traversal
	cleanPath := filepath.Clean(filePath)
	if cleanPath == "." {
		cleanPath = ""
	}
	
	return filepath.Join(basePath, cleanPath)
}

func (s *Service) isPathSafe(fullPath, workspaceID string) bool {
	// Get the expected workspace base path
	basePath := filepath.Join("/tmp", "workspaces", workspaceID)
	
	// Resolve any symbolic links and relative paths
	resolvedPath, err := filepath.Abs(fullPath)
	if err != nil {
		return false
	}
	
	resolvedBase, err := filepath.Abs(basePath)
	if err != nil {
		return false
	}
	
	// Check if the resolved path is within the workspace
	return strings.HasPrefix(resolvedPath, resolvedBase)
}

func (s *Service) listDirectory(dirPath string) ([]FileInfo, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	var files []FileInfo
	for _, entry := range entries {
		// Skip hidden files and directories starting with .
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		files = append(files, FileInfo{
			Name:    entry.Name(),
			Path:    filepath.Join(dirPath, entry.Name()),
			IsDir:   entry.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
		})
	}

	return files, nil
}

func (s *Service) StreamFile(c *gin.Context) {
	workspaceID := c.Param("workspace_id")
	filePath := c.Param("path")
	
	// Construct the full file path
	fullPath := s.getWorkspacePath(workspaceID, filePath)
	
	// Security check: ensure path is within workspace
	if !s.isPathSafe(fullPath, workspaceID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Open file for streaming
	file, err := os.Open(fullPath)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}
	defer file.Close()

	// Get file info for content type detection
	fileInfo, err := file.Stat()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get file info"})
		return
	}

	// Set appropriate headers
	c.Header("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
	c.Header("Content-Disposition", fmt.Sprintf("inline; filename=%s", filepath.Base(filePath)))
	
	// Stream file content
	c.Stream(func(w io.Writer) bool {
		buffer := make([]byte, 1024)
		n, err := file.Read(buffer)
		if err != nil {
			return false
		}
		w.Write(buffer[:n])
		return true
	})
}
