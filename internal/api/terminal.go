package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	s3client "github.com/vsay/vsay-agent-backend/internal/s3"
	"github.com/vsay/vsay-agent-backend/internal/store"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // TODO: Restrict in production
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type TerminalSession struct {
	ID            string
	AgentID       string
	UserID        string
	Username      string
	TenantID      string // For S3 recording path
	Source        string // "vscode", "cli", "ui"
	Browser       string // User-Agent
	OSInfo        string // Client OS
	IPAddress     string // Client IP
	Conn          *websocket.Conn
	CreatedAt     time.Time
	Commands      map[string]*CommandInfo // Track commands by commandID
	CurrentBuffer string                  // Buffer for current command being typed
	outputBuffer  string                  // Accumulates terminal output since last command
	castStart     time.Time               // When the session started (for asciicast timestamps)
	castEvents    []CastEvent             // Timed output events for asciicast v2 recording
	outputDirty   bool                    // True when buffer has new data not yet flushed to DB
	lastLogID     *primitive.ObjectID     // ID of the last logged command entry
	done          chan struct{}            // Closed when session ends, stops background goroutines
	tabPressed    bool                    // True when last keystroke was Tab; next PTY output is the completion suffix
	mu            sync.Mutex
}

// CommandInfo tracks command execution details
type CommandInfo struct {
	CommandID string
	Command   string
	Output    string
	Timestamp time.Time
	UserID    string
	AgentID   string
}

// CastEvent is a single timed event in an asciicast v2 recording.
type CastEvent struct {
	Time float64 // seconds since session start
	Type string  // "o" = output
	Data string
}

type TerminalManager struct {
	sessions map[string]*TerminalSession
	mu       sync.RWMutex
	logger   *zap.Logger
}

func NewTerminalManager(logger *zap.Logger) *TerminalManager {
	return &TerminalManager{
		sessions: make(map[string]*TerminalSession),
		logger:   logger,
	}
}

// SessionInfo contains metadata about a terminal session
type SessionInfo struct {
	Username  string
	TenantID  string
	Source    string
	Browser   string
	OSInfo    string
	IPAddress string
}

func (tm *TerminalManager) CreateSession(sessionID, agentID, userID string, conn *websocket.Conn, info *SessionInfo) *TerminalSession {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	now := time.Now()
	session := &TerminalSession{
		ID:        sessionID,
		AgentID:   agentID,
		UserID:    userID,
		Username:  info.Username,
		TenantID:  info.TenantID,
		Source:    info.Source,
		Browser:   info.Browser,
		OSInfo:    info.OSInfo,
		IPAddress: info.IPAddress,
		Conn:      conn,
		CreatedAt: now,
		castStart: now,
		Commands:  make(map[string]*CommandInfo),
		done:      make(chan struct{}),
	}

	tm.sessions[sessionID] = session
	tm.logger.Info("Terminal session created",
		zap.String("session_id", sessionID),
		zap.String("agent_id", agentID),
		zap.String("user_id", userID),
		zap.String("source", info.Source),
		zap.String("browser", info.Browser))

	return session
}

func (tm *TerminalManager) GetSession(sessionID string) (*TerminalSession, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	session, ok := tm.sessions[sessionID]
	return session, ok
}

func (tm *TerminalManager) DeleteSession(sessionID string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if session, ok := tm.sessions[sessionID]; ok {
		// Signal background goroutines (e.g., output flusher) to stop
		select {
		case <-session.done:
			// Already closed
		default:
			close(session.done)
		}
		_ = session.Conn.Close()
		delete(tm.sessions, sessionID)
		tm.logger.Info("Terminal session deleted", zap.String("session_id", sessionID))
	}
}

func (tm *TerminalManager) ListSessionsByUser(userID string) []string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var sessionIDs []string
	for _, session := range tm.sessions {
		if session.UserID == userID {
			sessionIDs = append(sessionIDs, session.ID)
		}
	}
	return sessionIDs
}

// SendOutput sends terminal output to WebSocket client and accumulates it in buffer
func (tm *TerminalManager) SendOutput(sessionID string, data []byte) error {
	tm.mu.RLock()
	session, ok := tm.sessions[sessionID]
	tm.mu.RUnlock()

	if !ok {
		return nil // Session not found, silently ignore
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	// If the last keystroke was Tab, capture the completion suffix the shell echoed
	// back and append it to CurrentBuffer so the logged command reflects the full
	// completed text (e.g. "cd Des" + Tab → PTY sends "ktop/" → buffer = "cd Desktop/").
	if session.tabPressed {
		if suffix := extractPrintableChars(data); suffix != "" {
			session.CurrentBuffer += suffix
			session.tabPressed = false
		}
	}

	// Accumulate output for logging and asciicast recording
	session.outputBuffer += string(data)
	elapsed := time.Since(session.castStart).Seconds()
	session.castEvents = append(session.castEvents, CastEvent{Time: elapsed, Type: "o", Data: string(data)})
	session.outputDirty = true

	message := map[string]interface{}{
		"type":   "output",
		"output": string(data),
	}

	return session.Conn.WriteJSON(message)
}

// WebSocket endpoint for terminal
func (h *Handler) TerminalWebSocket(c *gin.Context) {
	agentID := c.Param("agent_id")
	sessionID := c.Query("session_id")
	if sessionID == "" {
		sessionID = primitive.NewObjectID().Hex()
	}

	h.logger.Info("WebSocket connection attempt",
		zap.String("agent_id", agentID),
		zap.String("session_id", sessionID),
		zap.String("X-Username", c.GetHeader("X-Username")),
		zap.String("X-User-ID", c.GetHeader("X-User-ID")),
		zap.String("Authorization", c.GetHeader("Authorization")))

	// Get user info from context (must come through vsay-auth)
	userIDStr := c.GetString("user_id")
	username := c.GetString("username")

	h.logger.Info("WebSocket context values",
		zap.String("user_id_from_context", userIDStr),
		zap.String("username_from_context", username))

	// Require authentication through vsay-auth
	if userIDStr == "" || username == "" {
		h.logger.Error("WebSocket connection without authentication",
			zap.String("user_id", userIDStr),
			zap.String("username", username))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized - must authenticate through vsay-auth"})
		return
	}

	// Verify user owns the machine or has access
	userID, _ := primitive.ObjectIDFromHex(userIDStr)
	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil {
		h.logger.Error("Machine not found for WebSocket", zap.String("agent_id", agentID), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	// Check if user is owner OR has been granted access using username from context
	hasAccess := machine.OwnerID == userID
	if !hasAccess {
		for _, allowedUser := range machine.AllowedUsers {
			if allowedUser == username {
				hasAccess = true
				break
			}
		}
	}

	if !hasAccess {
		h.logger.Warn("User not authorized for machine",
			zap.String("user_id", userIDStr),
			zap.String("agent_id", agentID))
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logger.Error("Failed to upgrade to WebSocket", zap.Error(err))
		return
	}

	// Detect source from session_id prefix or query param
	source := c.Query("source")
	if source == "" {
		source = detectSourceFromSessionID(sessionID)
	}

	// Get client info from request
	browser := c.GetHeader("User-Agent")
	clientOS := c.Query("os_info")
	if clientOS == "" {
		clientOS = detectOSFromUserAgent(browser)
	}
	clientIP := c.ClientIP()

	h.logger.Info("WebSocket connection established",
		zap.String("session_id", sessionID),
		zap.String("agent_id", agentID),
		zap.String("user_id", userIDStr),
		zap.String("source", source),
		zap.String("browser", browser),
		zap.String("client_ip", clientIP))

	// Create session info using username from vsay-auth context
	sessionInfo := &SessionInfo{
		Username:  username,
		TenantID:  c.GetString("tenant_id"),
		Source:    source,
		Browser:   browser,
		OSInfo:    clientOS,
		IPAddress: clientIP,
	}

	// Create terminal session
	session := h.terminalManager.CreateSession(sessionID, agentID, userIDStr, conn, sessionInfo)

	// Save session to database
	go h.saveSessionToDB(session, machine.ID)

	// Periodically flush buffered output to DB so logs are visible in real-time
	go h.startOutputFlusher(session)

	// Handle WebSocket communication
	go h.handleTerminalSession(session)
}

func (h *Handler) handleTerminalSession(session *TerminalSession) {
	defer func() {
		// Save last command's accumulated output before closing
		session.mu.Lock()
		lastLogID := session.lastLogID
		lastOutput := session.outputBuffer
		castEvents := session.castEvents
		session.mu.Unlock()

		if lastLogID != nil && lastOutput != "" {
			if err := h.store.UpdateLogOutput(*lastLogID, lastOutput); err != nil {
				h.logger.Error("Failed to save final command output",
					zap.String("session_id", session.ID),
					zap.Error(err))
			}
		}

		h.terminalManager.DeleteSession(session.ID)
		// Close session in database
		if err := h.store.CloseSession(session.ID); err != nil {
			h.logger.Error("Failed to close session in database",
				zap.String("session_id", session.ID),
				zap.Error(err))
		} else {
			h.logger.Info("Session closed in database",
				zap.String("session_id", session.ID))
		}

		// Upload session recording to S3 (async, non-blocking)
		if len(castEvents) > 0 && session.TenantID != "" {
			go h.uploadSessionRecording(session, castEvents)
		}
	}()

	for {
		messageType, message, err := session.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				h.logger.Error("WebSocket error", zap.Error(err))
			}
			break
		}

		// Parse command
		var cmd struct {
			Type    string `json:"type"`
			Command string `json:"command"`
			Input   string `json:"input"`
		}

		if err := json.Unmarshal(message, &cmd); err != nil {
			h.logger.Error("Failed to parse command", zap.Error(err))
			continue
		}

		switch cmd.Type {
		case "command":
			// Send command to agent via gRPC
			go h.handleTerminalCommand(session, cmd.Command)

		case "input":
			// Handle stdin input (for interactive commands)
			h.logger.Debug("Terminal input received",
				zap.String("session_id", session.ID),
				zap.Int("input_len", len(cmd.Input)))

			// Track command for logging when Enter is pressed
			h.trackTerminalCommand(session, cmd.Input)

			// Send input to agent via gRPC
			if err := h.agentManager.SendTerminalInput(session.AgentID, session.ID, []byte(cmd.Input)); err != nil {
				h.logger.Warn("Agent not connected for terminal input",
					zap.String("session_id", session.ID),
					zap.String("agent_id", session.AgentID))
				// Don't send error to user, just log it and continue
				// Agent might reconnect later
			}

		case "resize":
			// Handle terminal resize
			h.logger.Debug("Terminal resize", zap.String("session", session.ID))

		default:
			h.logger.Warn("Unknown message type", zap.String("type", cmd.Type))
		}

		if messageType == websocket.TextMessage {
			// Echo for now (replace with actual command execution)
			h.sendTerminalOutput(session, string(message))
		}
	}
}

func (h *Handler) handleTerminalCommand(session *TerminalSession, command string) {
	// Send command to agent
	cmdID, err := h.agentManager.SendCommand(session.AgentID, command, nil)

	if err != nil {
		h.sendTerminalError(session, err.Error())
		return
	}

	// Track command in session
	session.mu.Lock()
	session.Commands[cmdID] = &CommandInfo{
		CommandID: cmdID,
		Command:   command,
		Timestamp: time.Now(),
		UserID:    session.UserID,
		AgentID:   session.AgentID,
	}
	session.mu.Unlock()

	// Track command metadata for logging
	h.agentManager.TrackCommand(cmdID, command, session.AgentID, session.UserID, session.Username, session.ID, true)

	// Send command started notification
	h.sendTerminalMessage(session, map[string]interface{}{
		"type":       "command_started",
		"command_id": cmdID,
		"command":    command,
	})

	// Note: Output will be received via agent stream callbacks
	// For now, just notify that command was sent
	h.sendTerminalMessage(session, map[string]interface{}{
		"type":    "info",
		"message": "Command sent to agent, waiting for response...",
	})
}

func (h *Handler) sendTerminalOutput(session *TerminalSession, output string) {
	session.mu.Lock()
	defer session.mu.Unlock()

	err := session.Conn.WriteMessage(websocket.TextMessage, []byte(output))
	if err != nil {
		h.logger.Error("Failed to send terminal output", zap.Error(err))
	}
}

func (h *Handler) sendTerminalMessage(session *TerminalSession, data interface{}) {
	session.mu.Lock()
	defer session.mu.Unlock()

	message, err := json.Marshal(data)
	if err != nil {
		h.logger.Error("Failed to marshal message", zap.Error(err))
		return
	}

	err = session.Conn.WriteMessage(websocket.TextMessage, message)
	if err != nil {
		h.logger.Error("Failed to send terminal message", zap.Error(err))
	}
}

func (h *Handler) sendTerminalError(session *TerminalSession, errorMsg string) {
	h.sendTerminalMessage(session, map[string]interface{}{
		"type":  "error",
		"error": errorMsg,
	})
}

// trackTerminalCommand tracks commands typed in PTY terminal for logging
func (h *Handler) trackTerminalCommand(session *TerminalSession, input string) {
	session.mu.Lock()
	defer session.mu.Unlock()

	// Process each character
	for _, char := range input {
		switch char {
		case '\r', '\n': // Enter key - command completed
			session.tabPressed = false
			if len(session.CurrentBuffer) > 0 {
				command := session.CurrentBuffer
				session.CurrentBuffer = ""

				// ── ATOMIC SNAPSHOT ──────────────────────────────────────────
				// Snapshot the output buffer RIGHT NOW while we hold the mutex.
				// This prevents the race where the PTY sends the new command's
				// output BEFORE the goroutine below gets to run, causing
				// the next command's output to appear under the wrong log entry.
				prevLogID := session.lastLogID
				prevOutput := session.outputBuffer
				session.outputBuffer = ""
				session.outputDirty = false
				session.lastLogID = nil
				// ─────────────────────────────────────────────────────────────

				// Log command asynchronously; pass the already-snapshotted values
				go h.logTerminalCommand(session, command, prevLogID, prevOutput)
			}
		case 127, 8: // Backspace
			if len(session.CurrentBuffer) > 0 {
				session.CurrentBuffer = session.CurrentBuffer[:len(session.CurrentBuffer)-1]
			}
		case '\t': // Tab — shell will echo the completion suffix via PTY output
			session.tabPressed = true
		case 3: // Ctrl+C
			session.CurrentBuffer = ""
			session.tabPressed = false
		case 4: // Ctrl+D
			session.CurrentBuffer = ""
			session.tabPressed = false
		default:
			// Add printable characters to buffer
			if char >= 32 && char < 127 {
				session.CurrentBuffer += string(char)
			}
		}
	}
}

// logTerminalCommand logs a completed terminal command to database.
// prevLogID and prevOutput are the already-snapshotted output for the PREVIOUS
// command — they were captured atomically in trackTerminalCommand while holding
// the session mutex, so they are safe to use here without re-locking.
func (h *Handler) logTerminalCommand(session *TerminalSession, command string, prevLogID *primitive.ObjectID, prevOutput string) {
	// Persist previous command's output (snapshot taken at Enter-press time)
	if prevLogID != nil && prevOutput != "" {
		go func(id primitive.ObjectID, out string) {
			if err := h.store.UpdateLogOutput(id, out); err != nil {
				h.logger.Error("Failed to update log output",
					zap.String("log_id", id.Hex()),
					zap.Error(err))
			}
		}(*prevLogID, prevOutput)
	}

	// Get machine info
	machine, err := h.store.GetMachineByAgentID(session.AgentID)
	if err != nil {
		h.logger.Error("Failed to get machine for terminal command logging",
			zap.String("agent_id", session.AgentID),
			zap.Error(err))
		return
	}

	// Parse user ID
	userID, err := primitive.ObjectIDFromHex(session.UserID)
	if err != nil {
		h.logger.Error("Invalid user ID for logging",
			zap.String("user_id", session.UserID),
			zap.Error(err))
		return
	}

	// Create log entry with full session info
	logEntry := &store.LogEntry{
		MachineID: machine.ID,
		UserID:    userID,
		Username:  session.Username,
		SessionID: session.ID,
		Command:   command,
		Timestamp: time.Now(),
		Success:   true, // PTY commands don't have exit codes
		Source:    session.Source,
		Browser:   session.Browser,
		OSInfo:    session.OSInfo,
		IPAddress: session.IPAddress,
	}

	if err := h.store.CreateLog(logEntry); err != nil {
		h.logger.Error("Failed to log terminal command",
			zap.String("command", command),
			zap.String("session_id", session.ID),
			zap.Error(err))
	} else {
		// Track log ID so we can save its output when next command arrives
		// Copy ID to heap-allocated variable to avoid dangling pointer
		logID := logEntry.ID
		session.mu.Lock()
		session.lastLogID = &logID
		session.mu.Unlock()

		// Increment session command count
		go h.store.IncrementSessionCommandCount(session.ID)

		h.logger.Info("Terminal command logged",
			zap.String("command", command),
			zap.String("session_id", session.ID),
			zap.String("source", session.Source),
			zap.String("machine_id", machine.ID.Hex()),
			zap.String("user_id", userID.Hex()))
	}
}

// startOutputFlusher periodically saves buffered terminal output to DB.
// This ensures output appears in logs without waiting for the next command.
func (h *Handler) startOutputFlusher(session *TerminalSession) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			session.mu.Lock()
			// Only write if buffer changed since last flush (avoid redundant DB writes)
			if session.lastLogID != nil && session.outputDirty && session.outputBuffer != "" {
				logID := *session.lastLogID
				output := session.outputBuffer
				session.outputDirty = false // Mark clean — reset to true when new output arrives
				session.mu.Unlock()
				if err := h.store.UpdateLogOutput(logID, output); err != nil {
					h.logger.Error("Output flusher: failed to save output",
						zap.String("session_id", session.ID),
						zap.Error(err))
				}
			} else {
				session.mu.Unlock()
			}
		case <-session.done:
			return
		}
	}
}

// uploadSessionRecording serialises the session as an asciicast v2 file and uploads it to S3.
func (h *Handler) uploadSessionRecording(session *TerminalSession, events []CastEvent) {
	tenantCfg, err := h.store.GetTenantConfig(session.TenantID)
	if err != nil || !tenantCfg.S3.Enabled {
		return // S3 not configured — skip silently
	}

	s3cfg := tenantCfg.S3
	client, err := s3client.NewClient(s3cfg.Endpoint, s3cfg.Protocol, s3cfg.AccessKey, s3cfg.SecretKey, s3cfg.Region, s3cfg.Bucket)
	if err != nil {
		h.logger.Error("S3 client init failed for recording",
			zap.String("session_id", session.ID), zap.Error(err))
		return
	}

	machine, err := h.store.GetMachineByAgentID(session.AgentID)
	if err != nil {
		h.logger.Error("Machine lookup failed for recording",
			zap.String("session_id", session.ID), zap.Error(err))
		return
	}

	castData := serializeAsciicast(session, events)

	// S3 key: webxterm/{tenant}/{machine}/{session}/{username}/videos/session.cast
	key := fmt.Sprintf("webxterm/%s/%s/%s/%s/videos/session.cast",
		session.TenantID, machine.Name, session.ID, session.Username)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := client.Upload(ctx, key, castData, "application/x-asciicast"); err != nil {
		h.logger.Error("Failed to upload session recording to S3",
			zap.String("session_id", session.ID),
			zap.String("key", key),
			zap.Error(err))
		return
	}

	duration := int64(time.Since(session.CreatedAt).Seconds())
	recording := &store.SessionRecording{
		SessionID:   session.ID,
		MachineID:   machine.ID,
		MachineName: machine.Name,
		TenantID:    session.TenantID,
		Username:    session.Username,
		S3Key:       key,
		SizeBytes:   int64(len(castData)),
		Duration:    duration,
	}

	if err := h.store.CreateRecording(recording); err != nil {
		h.logger.Error("Failed to save recording metadata",
			zap.String("session_id", session.ID), zap.Error(err))
		return
	}

	h.logger.Info("Session recording uploaded to S3",
		zap.String("session_id", session.ID),
		zap.String("key", key),
		zap.Int("size_bytes", len(castData)))
}

// serializeAsciicast builds an asciicast v2 (NDJSON) file from session events.
// First line: JSON header. Each subsequent line: [elapsed_seconds, "o", data].
func serializeAsciicast(session *TerminalSession, events []CastEvent) []byte {
	type castHeader struct {
		Version   int    `json:"version"`
		Width     int    `json:"width"`
		Height    int    `json:"height"`
		Timestamp int64  `json:"timestamp"`
		Title     string `json:"title"`
	}
	hdr := castHeader{
		Version:   2,
		Width:     220,
		Height:    50,
		Timestamp: session.CreatedAt.Unix(),
		Title:     fmt.Sprintf("Session %s — %s", session.ID[:8], session.Username),
	}

	var buf bytes.Buffer
	headerBytes, _ := json.Marshal(hdr)
	buf.Write(headerBytes)
	buf.WriteByte('\n')

	for _, ev := range events {
		line, _ := json.Marshal([]interface{}{ev.Time, ev.Type, ev.Data})
		buf.Write(line)
		buf.WriteByte('\n')
	}

	return buf.Bytes()
}

// REST API for terminal sessions
func (h *Handler) ListTerminalSessions(c *gin.Context) {
	userID := c.GetString("user_id")
	sessions := h.terminalManager.ListSessionsByUser(userID)

	c.JSON(http.StatusOK, gin.H{
		"sessions": sessions,
	})
}

func (h *Handler) DeleteTerminalSession(c *gin.Context) {
	sessionID := c.Param("session_id")
	userID := c.GetString("user_id")

	// Verify session belongs to user
	session, ok := h.terminalManager.GetSession(sessionID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}

	if session.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
		return
	}

	h.terminalManager.DeleteSession(sessionID)

	// Close session in database
	go h.store.CloseSession(sessionID)

	c.JSON(http.StatusOK, gin.H{"message": "Session deleted"})
}

// extractPrintableChars strips ANSI/VT escape sequences and control characters
// from PTY output, returning only printable ASCII text. Used to capture tab
// completion suffixes from shell echo (e.g. "ktop/" when completing "Des"→"Desktop/").
func extractPrintableChars(data []byte) string {
	var result strings.Builder
	i := 0
	for i < len(data) {
		b := data[i]
		if b == 0x1b { // ESC — skip the entire escape sequence
			i++
			if i < len(data) && data[i] == '[' {
				// CSI sequence: ESC [ ... <final-byte>  (final byte is a letter)
				i++
				for i < len(data) && !((data[i] >= 'A' && data[i] <= 'Z') || (data[i] >= 'a' && data[i] <= 'z')) {
					i++
				}
				i++ // skip final byte
			} else if i < len(data) {
				i++ // two-char escape sequence (e.g. ESC M)
			}
		} else if b >= 32 && b < 127 {
			// Printable ASCII (space through ~)
			result.WriteByte(b)
			i++
		} else {
			i++ // skip all other control chars (\r, \n, \t, BEL, etc.)
		}
	}
	return result.String()
}

// detectSourceFromSessionID detects the source from session_id prefix
func detectSourceFromSessionID(sessionID string) string {
	if len(sessionID) >= 6 && sessionID[:6] == "vscode" {
		return "vscode"
	}
	if len(sessionID) >= 3 && sessionID[:3] == "cli" {
		return "cli"
	}
	if len(sessionID) >= 7 && sessionID[:7] == "session" {
		return "ui"
	}
	return "ui" // default to ui
}

// detectOSFromUserAgent extracts OS info from User-Agent string
func detectOSFromUserAgent(userAgent string) string {
	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "windows"):
		return "Windows"
	case strings.Contains(ua, "mac os") || strings.Contains(ua, "macintosh"):
		return "macOS"
	case strings.Contains(ua, "linux"):
		return "Linux"
	case strings.Contains(ua, "android"):
		return "Android"
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		return "iOS"
	default:
		return "Unknown"
	}
}

// saveSessionToDB saves a new session to the database (or reactivates existing one)
func (h *Handler) saveSessionToDB(session *TerminalSession, machineID primitive.ObjectID) {
	userID, err := primitive.ObjectIDFromHex(session.UserID)
	if err != nil {
		h.logger.Error("Invalid user ID for session", zap.String("user_id", session.UserID), zap.Error(err))
		return
	}

	// Check if session already exists (reconnection case)
	existingSession, err := h.store.GetSessionByID(session.ID)
	if err == nil && existingSession != nil {
		// Session exists - reactivate it
		if err := h.store.UpdateSessionStatus(session.ID, "active"); err != nil {
			h.logger.Error("Failed to reactivate session",
				zap.String("session_id", session.ID),
				zap.Error(err))
		} else {
			h.logger.Info("Session reactivated",
				zap.String("session_id", session.ID),
				zap.String("source", session.Source))
		}
		return
	}

	// Create new session
	dbSession := &store.Session{
		SessionID:    session.ID,
		MachineID:    machineID,
		AgentID:      session.AgentID,
		UserID:       userID,
		Username:     session.Username,
		Source:       session.Source,
		Browser:      session.Browser,
		OSInfo:       session.OSInfo,
		IPAddress:    session.IPAddress,
		Status:       "active",
		CommandCount: 0,
	}

	if err := h.store.CreateSession(dbSession); err != nil {
		h.logger.Error("Failed to save session to database",
			zap.String("session_id", session.ID),
			zap.Error(err))
	} else {
		h.logger.Info("Session saved to database",
			zap.String("session_id", session.ID),
			zap.String("source", session.Source))
	}
}
