package websocket

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"clouddev-server/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	logger     logger.Logger
	mu         sync.RWMutex
}

type Client struct {
	hub         *Hub
	conn        *websocket.Conn
	send        chan []byte
	userID      string
	workspaceID string
	sessionID   string
}

type Message struct {
	Type        string      `json:"type"`
	WorkspaceID string      `json:"workspace_id"`
	UserID      string      `json:"user_id"`
	SessionID   string      `json:"session_id"`
	Timestamp   time.Time   `json:"timestamp"`
	Data        interface{} `json:"data"`
}

type FileChangeMessage struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Operation string `json:"operation"` // create, update, delete
	Line      int    `json:"line,omitempty"`
	Column    int    `json:"column,omitempty"`
}

type CursorMessage struct {
	Path   string `json:"path"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
	UserID string `json:"user_id"`
}

type TerminalMessage struct {
	TerminalID string `json:"terminal_id"`
	Data       string `json:"data"`
	Type       string `json:"type"` // input, output, resize
	Rows       int    `json:"rows,omitempty"`
	Cols       int    `json:"cols,omitempty"`
}

type UserPresenceMessage struct {
	UserID string `json:"user_id"`
	Status string `json:"status"` // online, offline, typing
	Path   string `json:"path,omitempty"`
}

const (
	// Time allowed to write a message to the peer
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer
	maxMessageSize = 512 * 1024 // 512KB
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// TODO: Implement proper origin checking
		return true
	},
}

func NewHub(logger logger.Logger) *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		logger:     logger,
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			
			h.logger.Info("WebSocket client connected", 
				"user_id", client.userID, 
				"workspace_id", client.workspaceID,
				"session_id", client.sessionID)
			
			// Send user presence notification
			h.broadcastUserPresence(client.userID, client.workspaceID, "online")
			
		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			
			h.logger.Info("WebSocket client disconnected", 
				"user_id", client.userID, 
				"workspace_id", client.workspaceID,
				"session_id", client.sessionID)
			
			// Send user presence notification
			h.broadcastUserPresence(client.userID, client.workspaceID, "offline")
			
		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					delete(h.clients, client)
					close(client.send)
				}
			}
			h.mu.RUnlock()
		}
	}
}

func (h *Hub) HandleWebSocket(c *gin.Context) {
	workspaceID := c.Param("workspace_id")
	userID := c.GetString("user_id")
	
	if workspaceID == "" || userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing workspace_id or user_id"})
		return
	}
	
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logger.Error("WebSocket upgrade failed", "error", err)
		return
	}
	
	sessionID := generateSessionID()
	client := &Client{
		hub:         h,
		conn:        conn,
		send:        make(chan []byte, 256),
		userID:      userID,
		workspaceID: workspaceID,
		sessionID:   sessionID,
	}
	
	client.hub.register <- client
	
	// Start goroutines for reading and writing
	go client.writePump()
	go client.readPump()
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	
	for {
		_, messageBytes, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.hub.logger.Error("WebSocket error", "error", err)
			}
			break
		}
		
		// Parse message
		var msg Message
		if err := json.Unmarshal(messageBytes, &msg); err != nil {
			c.hub.logger.Error("Invalid WebSocket message", "error", err)
			continue
		}
		
		// Set message metadata
		msg.UserID = c.userID
		msg.WorkspaceID = c.workspaceID
		msg.SessionID = c.sessionID
		msg.Timestamp = time.Now()
		
		// Handle different message types
		c.handleMessage(&msg)
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			
			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)
			
			// Add queued chat messages to the current websocket message
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}
			
			if err := w.Close(); err != nil {
				return
			}
			
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *Client) handleMessage(msg *Message) {
	switch msg.Type {
	case "file_change":
		c.handleFileChange(msg)
	case "cursor_position":
		c.handleCursorPosition(msg)
	case "terminal":
		c.handleTerminal(msg)
	case "user_presence":
		c.handleUserPresence(msg)
	case "ping":
		c.handlePing(msg)
	default:
		c.hub.logger.Warn("Unknown message type", "type", msg.Type)
	}
}

func (c *Client) handleFileChange(msg *Message) {
	// Validate that the user has access to the workspace
	if msg.WorkspaceID != c.workspaceID {
		return
	}
	
	// Parse file change data
	var fileChange FileChangeMessage
	if data, ok := msg.Data.(map[string]interface{}); ok {
		dataBytes, _ := json.Marshal(data)
		json.Unmarshal(dataBytes, &fileChange)
	}
	
	// Broadcast to other clients in the same workspace
	c.broadcastToWorkspace(msg)
	
	c.hub.logger.Info("File change", 
		"user_id", msg.UserID,
		"workspace_id", msg.WorkspaceID,
		"path", fileChange.Path,
		"operation", fileChange.Operation)
}

func (c *Client) handleCursorPosition(msg *Message) {
	// Validate that the user has access to the workspace
	if msg.WorkspaceID != c.workspaceID {
		return
	}
	
	// Broadcast cursor position to other clients in the same workspace
	c.broadcastToWorkspace(msg)
}

func (c *Client) handleTerminal(msg *Message) {
	// Validate that the user has access to the workspace
	if msg.WorkspaceID != c.workspaceID {
		return
	}
	
	// Parse terminal data
	var terminalMsg TerminalMessage
	if data, ok := msg.Data.(map[string]interface{}); ok {
		dataBytes, _ := json.Marshal(data)
		json.Unmarshal(dataBytes, &terminalMsg)
	}
	
	// TODO: Forward terminal input to the actual terminal session
	// This would involve communication with the container/terminal service
	
	// Broadcast terminal output to other clients in the same workspace
	c.broadcastToWorkspace(msg)
}

func (c *Client) handleUserPresence(msg *Message) {
	// Validate that the user has access to the workspace
	if msg.WorkspaceID != c.workspaceID {
		return
	}
	
	// Broadcast presence update to other clients in the same workspace
	c.broadcastToWorkspace(msg)
}

func (c *Client) handlePing(msg *Message) {
	// Respond with pong
	response := Message{
		Type:        "pong",
		WorkspaceID: c.workspaceID,
		UserID:      c.userID,
		SessionID:   c.sessionID,
		Timestamp:   time.Now(),
	}
	
	c.sendMessage(response)
}

func (c *Client) broadcastToWorkspace(msg *Message) {
	messageBytes, err := json.Marshal(msg)
	if err != nil {
		c.hub.logger.Error("Failed to marshal message", "error", err)
		return
	}
	
	c.hub.mu.RLock()
	for client := range c.hub.clients {
		// Only send to clients in the same workspace, excluding the sender
		if client.workspaceID == c.workspaceID && client.sessionID != c.sessionID {
			select {
			case client.send <- messageBytes:
			default:
				close(client.send)
				delete(c.hub.clients, client)
			}
		}
	}
	c.hub.mu.RUnlock()
}

func (c *Client) sendMessage(msg Message) {
	messageBytes, err := json.Marshal(msg)
	if err != nil {
		c.hub.logger.Error("Failed to marshal message", "error", err)
		return
	}
	
	select {
	case c.send <- messageBytes:
	default:
		close(c.send)
	}
}

func (h *Hub) broadcastUserPresence(userID, workspaceID, status string) {
	msg := Message{
		Type:        "user_presence",
		WorkspaceID: workspaceID,
		UserID:      userID,
		Timestamp:   time.Now(),
		Data: UserPresenceMessage{
			UserID: userID,
			Status: status,
		},
	}
	
	messageBytes, err := json.Marshal(msg)
	if err != nil {
		h.logger.Error("Failed to marshal presence message", "error", err)
		return
	}
	
	h.mu.RLock()
	for client := range h.clients {
		if client.workspaceID == workspaceID {
			select {
			case client.send <- messageBytes:
			default:
				close(client.send)
				delete(h.clients, client)
			}
		}
	}
	h.mu.RUnlock()
}

// GetWorkspaceUsers returns a list of users currently connected to a workspace
func (h *Hub) GetWorkspaceUsers(workspaceID string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	userSet := make(map[string]bool)
	for client := range h.clients {
		if client.workspaceID == workspaceID {
			userSet[client.userID] = true
		}
	}
	
	users := make([]string, 0, len(userSet))
	for userID := range userSet {
		users = append(users, userID)
	}
	
	return users
}

// BroadcastToWorkspace sends a message to all clients in a specific workspace
func (h *Hub) BroadcastToWorkspace(workspaceID string, messageType string, data interface{}) {
	msg := Message{
		Type:        messageType,
		WorkspaceID: workspaceID,
		Timestamp:   time.Now(),
		Data:        data,
	}
	
	messageBytes, err := json.Marshal(msg)
	if err != nil {
		h.logger.Error("Failed to marshal broadcast message", "error", err)
		return
	}
	
	h.mu.RLock()
	for client := range h.clients {
		if client.workspaceID == workspaceID {
			select {
			case client.send <- messageBytes:
			default:
				close(client.send)
				delete(h.clients, client)
			}
		}
	}
	h.mu.RUnlock()
}

func generateSessionID() string {
	// Generate a unique session ID
	return time.Now().Format("20060102150405") + "-" + randString(8)
}

func randString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}
