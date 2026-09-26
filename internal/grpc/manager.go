package grpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vsay/vsay-agent-backend/internal/metrics"
	agentv1 "github.com/vsay/vsay-agent-backend/proto/agent/v1"
)

// AgentConnection represents an active gRPC connection from an agent
type AgentConnection struct {
	AgentID   string
	Stream    agentv1.AgentService_StreamServer
	LastSeen  time.Time
	Ctx       context.Context
	Cancel    context.CancelFunc
	InputChan chan *agentv1.ServerMessage // Messages to send TO agent (terminal, commands)
	// DesktopChan is a SEPARATE, large lane dedicated to remote-desktop (RDP/VNC)
	// byte traffic. RDP pushes heavy bitmap bursts; on the shared 100-slot InputChan
	// those bursts overflow and SendTerminalInput drops them (100ms timeout) → the
	// desktop tunnel tears down. Isolating desktop bytes here (with a blocking,
	// backpressure send — never dropped) keeps RDP alive and leaves the terminal
	// path byte-for-byte unchanged (Linux terminal is unaffected).
	DesktopChan chan *agentv1.ServerMessage
}

// CommandMetadata tracks command execution context
type CommandMetadata struct {
	CommandID  string
	Command    string
	AgentID    string
	UserID     string
	Username   string
	Timestamp  time.Time
	SessionID  string
	IsTerminal bool
}

type AgentManager struct {
	mu              sync.RWMutex
	connections     map[string]*AgentConnection
	commandMetadata map[string]*CommandMetadata // Track command metadata by commandID
}

func NewAgentManager() *AgentManager {
	return &AgentManager{
		connections:     make(map[string]*AgentConnection),
		commandMetadata: make(map[string]*CommandMetadata),
	}
}

func (m *AgentManager) AddConnection(agentID string, stream agentv1.AgentService_StreamServer) *AgentConnection {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx, cancel := context.WithCancel(stream.Context())
	conn := &AgentConnection{
		AgentID:     agentID,
		Stream:      stream,
		LastSeen:    time.Now(),
		Ctx:         ctx,
		Cancel:      cancel,
		InputChan:   make(chan *agentv1.ServerMessage, 100),
		DesktopChan: make(chan *agentv1.ServerMessage, 2048),
	}

	m.connections[agentID] = conn
	metrics.GRPCActiveConnections.Inc()
	metrics.GRPCConnectionsTotal.Inc()
	return conn
}

func (m *AgentManager) RemoveConnection(agentID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if conn, exists := m.connections[agentID]; exists {
		conn.Cancel()
		close(conn.InputChan)
		delete(m.connections, agentID)
		metrics.GRPCActiveConnections.Dec()
		metrics.GRPCDisconnectionsTotal.Inc()
	}
}

func (m *AgentManager) GetConnection(agentID string) *AgentConnection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connections[agentID]
}

func (m *AgentManager) IsAgentConnected(agentID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.connections[agentID]
	return exists
}

func (m *AgentManager) GetConnectedAgents() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	agents := make([]string, 0, len(m.connections))
	for agentID := range m.connections {
		agents = append(agents, agentID)
	}
	return agents
}

func (m *AgentManager) SendCommand(agentID string, cmd string, env map[string]string) (string, error) {
	conn := m.GetConnection(agentID)
	if conn == nil {
		return "", fmt.Errorf("agent not connected")
	}

	cmdID := fmt.Sprintf("cmd_%d", time.Now().UnixNano())
	msg := &agentv1.ServerMessage{
		Payload: &agentv1.ServerMessage_Command{
			Command: &agentv1.CommandRequest{
				CommandId: cmdID,
				Command:   cmd,
				Env:       env,
			},
		},
	}

	select {
	case conn.InputChan <- msg:
		return cmdID, nil
	case <-time.After(time.Second):
		return "", fmt.Errorf("timeout sending command to agent")
	}
}

func (m *AgentManager) SendTerminalInput(agentID, sessionID string, data []byte) error {
	conn := m.GetConnection(agentID)
	if conn == nil {
		return fmt.Errorf("agent not connected")
	}

	msg := &agentv1.ServerMessage{
		Payload: &agentv1.ServerMessage_TerminalInput{
			TerminalInput: &agentv1.TerminalInput{
				SessionId: sessionID,
				Data:      data,
			},
		},
	}

	select {
	case conn.InputChan <- msg:
		return nil
	case <-time.After(100 * time.Millisecond):
		return fmt.Errorf("buffer full")
	}
}

// SendDesktopInput queues a remote-desktop (RDP/VNC) byte message on the dedicated
// DesktopChan. Unlike SendTerminalInput it BLOCKS until there's room (or the agent
// disconnects) instead of dropping after 100ms — this applies TCP backpressure to
// guacd rather than killing the tunnel when RDP's bitmap stream outruns the wire.
// All of a tunnel's messages (connect/data/close) go through this single channel, so
// their order is preserved.
func (m *AgentManager) SendDesktopInput(agentID, sessionID string, data []byte) error {
	conn := m.GetConnection(agentID)
	if conn == nil {
		return fmt.Errorf("agent not connected")
	}

	msg := &agentv1.ServerMessage{
		Payload: &agentv1.ServerMessage_TerminalInput{
			TerminalInput: &agentv1.TerminalInput{
				SessionId: sessionID,
				Data:      data,
			},
		},
	}

	select {
	case conn.DesktopChan <- msg:
		return nil
	case <-conn.Ctx.Done():
		return fmt.Errorf("agent connection closed")
	}
}

// TrackCommand stores command metadata for logging
func (m *AgentManager) TrackCommand(cmdID, command, agentID, userID, username, sessionID string, isTerminal bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.commandMetadata[cmdID] = &CommandMetadata{
		CommandID:  cmdID,
		Command:    command,
		AgentID:    agentID,
		UserID:     userID,
		Username:   username,
		Timestamp:  time.Now(),
		SessionID:  sessionID,
		IsTerminal: isTerminal,
	}
}

// GetCommandMetadata retrieves command metadata
func (m *AgentManager) GetCommandMetadata(cmdID string) *CommandMetadata {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.commandMetadata[cmdID]
}

// RemoveCommandMetadata cleans up after command completion
func (m *AgentManager) RemoveCommandMetadata(cmdID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.commandMetadata, cmdID)
}

// BroadcastCARotation sends the new CA cert PEM to ALL currently connected agents
// over their existing secure gRPC streams. Agents receive it, save the new CA,
// re-sign their client cert (old CA still trusted during grace period), and reconnect.
// This eliminates InsecureSkipVerify for agents that are online during rotation.
func (m *AgentManager) BroadcastCARotation(newCAPEM string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	msg := &agentv1.ServerMessage{
		Payload: &agentv1.ServerMessage_Command{
			Command: &agentv1.CommandRequest{
				CommandId: "__vsay_ca_rotation__",
				Command:   newCAPEM,
			},
		},
	}

	for agentID, conn := range m.connections {
		select {
		case conn.InputChan <- msg:
		default:
			// Buffer full — agent will catch up via fingerprint polling
			_ = agentID
		}
	}
}

// SendUpdateCommand triggers a self-update on a connected agent. downloadURL is the
// full URL of the new agent package; the agent downloads it, hot-swaps its binary,
// and restarts. Uses the reserved "__vsay_update__" command id so the agent routes
// it to its self-update handler instead of the shell executor.
func (m *AgentManager) SendUpdateCommand(agentID string, downloadURL string) error {
	conn := m.GetConnection(agentID)
	if conn == nil {
		return fmt.Errorf("agent not connected")
	}

	msg := &agentv1.ServerMessage{
		Payload: &agentv1.ServerMessage_Command{
			Command: &agentv1.CommandRequest{
				CommandId: "__vsay_update__",
				Command:   downloadURL,
			},
		},
	}

	select {
	case conn.InputChan <- msg:
		return nil
	case <-time.After(time.Second):
		return fmt.Errorf("timeout sending update command to agent")
	}
}

// KickAgent forcibly closes the gRPC connection for a specific agent.
// Used after machine revocation to immediately cut off access.
// The agent's reconnect loop will attempt to re-register, which will fail
// because revoked machines are rejected at the sign-cert and Register endpoints.
func (m *AgentManager) KickAgent(agentID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if conn, exists := m.connections[agentID]; exists {
		conn.Cancel()
		// Don't close InputChan here — that's handled by RemoveConnection
		// called from the stream goroutine when it sees the context cancelled.
	}
}
