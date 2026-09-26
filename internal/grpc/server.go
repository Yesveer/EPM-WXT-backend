package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/vsay/vsay-agent-backend/internal/email"
	"github.com/vsay/vsay-agent-backend/internal/metrics"
	"github.com/vsay/vsay-agent-backend/internal/store"
	agentv1 "github.com/vsay/vsay-agent-backend/proto/agent/v1"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AgentServer struct {
	agentv1.UnimplementedAgentServiceServer
	store           store.Store
	manager         *AgentManager
	logger          *zap.Logger
	terminalManager TerminalManager
	rdpHandler      RDPDataHandler
	rcHandler       RDPDataHandler
	email           *email.Service
}

// TerminalManager interface for forwarding terminal output
type TerminalManager interface {
	SendOutput(sessionID string, data []byte) error
}

// RDPDataHandler receives agent output for RDP tunnel sessions (session IDs prefixed
// "rdp_"). Kept as an interface to avoid an import cycle with the api package.
type RDPDataHandler interface {
	HandleAgentData(sessionID string, data []byte)
}

func NewAgentServer(s store.Store, m *AgentManager, l *zap.Logger) *AgentServer {
	return &AgentServer{
		store:   s,
		manager: m,
		logger:  l,
		email:   email.New(),
	}
}

// SetTerminalManager sets the terminal manager for forwarding output
func (s *AgentServer) SetTerminalManager(tm TerminalManager) {
	s.terminalManager = tm
}

// accessEventMsg is the JSON the agent sends in a StatusUpdate("__access_event__").
type accessEventMsg struct {
	Action    string `json:"action"` // "login" | "logout"
	Protocol  string `json:"protocol"`
	OSUser    string `json:"os_user"`
	SourceIP  string `json:"source_ip"`
	Line      string `json:"line"`
	Timestamp string `json:"timestamp"` // RFC3339
	Seed      bool   `json:"seed"`      // pre-existing session on agent start — record, don't email
}

// handleAgentStats stores the agent process's latest resource usage.
func (s *AgentServer) handleAgentStats(agentID, raw string) {
	var st struct {
		CPUPercent   float64 `json:"cpu_percent"`
		MemoryMB     float64 `json:"memory_mb"`
		Goroutines   int     `json:"goroutines"`
		UptimeSec    int64   `json:"uptime_sec"`
		Version      string  `json:"version"`
		OpenTunnels  int     `json:"open_tunnels"`
		OpenSessions int     `json:"open_sessions"`
	}
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return
	}
	_ = s.store.UpsertAgentStats(agentID, &store.AgentStats{
		CPUPercent:   st.CPUPercent,
		MemoryMB:     st.MemoryMB,
		Goroutines:   st.Goroutines,
		UptimeSec:    st.UptimeSec,
		Version:      st.Version,
		OpenTunnels:  st.OpenTunnels,
		OpenSessions: st.OpenSessions,
	})
}

// handleAccessEvent records an external SSH/RDP login/logout the agent detected, and
// on a new login alerts the machine's notify-emails. Best-effort.
// accessSnapshotMsg is the full session list the agent sends on start, in a
// StatusUpdate("__access_snapshot__").
type accessSnapshotMsg struct {
	Sessions []struct {
		Protocol  string `json:"protocol"`
		OSUser    string `json:"os_user"`
		SourceIP  string `json:"source_ip"`
		Line      string `json:"line"`
		Timestamp string `json:"timestamp"`
	} `json:"sessions"`
}

// handleAccessSnapshot reconciles the recorded sessions against what the
// machine actually has open.
//
// Two problems only a snapshot can fix. Sessions that ended while the agent
// was stopped are never reported as logouts — nothing saw them end — so they
// stayed "active" indefinitely. And sessions that were already recorded got
// inserted again on every restart. Reconciling handles both: close what is
// gone, add what is new, leave the rest alone.
func (s *AgentServer) handleAccessSnapshot(agentID, raw string) {
	var snap accessSnapshotMsg
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		s.logger.Warn("access snapshot: bad payload", zap.String("agent_id", agentID), zap.Error(err))
		return
	}

	machine, err := s.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		return
	}

	keep := make([]store.AccessEventKey, 0, len(snap.Sessions))
	for _, sess := range snap.Sessions {
		keep = append(keep, store.AccessEventKey{OSUser: sess.OSUser, Line: sess.Line})
	}

	now := time.Now()
	closed, err := s.store.CloseStaleAccessEvents(agentID, keep, now)
	if err != nil {
		s.logger.Warn("access snapshot: closing stale sessions failed", zap.Error(err))
	}

	// Collapse rows left over from before insert was deduplicated. Reconciling
	// alone would keep them: each one matches a session that genuinely is open.
	deduped, err := s.store.DedupeActiveAccessEvents(agentID, now)
	if err != nil {
		s.logger.Warn("access snapshot: dedupe failed", zap.Error(err))
	}

	added := 0
	for _, sess := range snap.Sessions {
		open, err := s.store.HasActiveAccessEvent(agentID, sess.OSUser, sess.Line)
		if err != nil || open {
			continue
		}
		ts, perr := time.Parse(time.RFC3339, sess.Timestamp)
		if perr != nil {
			ts = time.Now()
		}
		rec := &store.AccessEvent{
			MachineID:   machine.ID,
			AgentID:     agentID,
			MachineName: machine.Name,
			TenantID:    machine.TenantID,
			Protocol:    sess.Protocol,
			OSUser:      sess.OSUser,
			SourceIP:    sess.SourceIP,
			Line:        sess.Line,
			Active:      true,
			LoginAt:     ts,
		}
		if err := s.store.CreateAccessEvent(rec); err != nil {
			s.logger.Warn("access snapshot: store failed", zap.Error(err))
			continue
		}
		added++
	}

	s.logger.Info("Reconciled external login sessions",
		zap.String("machine", machine.Name),
		zap.Int("reported", len(snap.Sessions)),
		zap.Int("added", added),
		zap.Int64("closed_stale", closed),
		zap.Int64("deduped", deduped))
}

func (s *AgentServer) handleAccessEvent(agentID, raw string) {
	var ev accessEventMsg
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		s.logger.Warn("access event: bad payload", zap.String("agent_id", agentID), zap.Error(err))
		return
	}

	machine, err := s.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		return
	}

	ts, perr := time.Parse(time.RFC3339, ev.Timestamp)
	if perr != nil {
		ts = time.Now()
	}

	if ev.Action == "logout" {
		_ = s.store.CloseAccessEvent(agentID, ev.OSUser, ev.Line, ts)
		s.logger.Info("External access ended",
			zap.String("agent_id", agentID), zap.String("os_user", ev.OSUser),
			zap.String("protocol", ev.Protocol), zap.String("line", ev.Line))
		return
	}

	// login — idempotent.
	//
	// The agent re-reports every existing session on start, so without this an
	// unchanged login gained a fresh row on every agent restart and the portal
	// showed the same person logged in several times over.
	if open, err := s.store.HasActiveAccessEvent(agentID, ev.OSUser, ev.Line); err == nil && open {
		return
	}

	rec := &store.AccessEvent{
		MachineID:   machine.ID,
		AgentID:     agentID,
		MachineName: machine.Name,
		TenantID:    machine.TenantID,
		Protocol:    ev.Protocol,
		OSUser:      ev.OSUser,
		SourceIP:    ev.SourceIP,
		Line:        ev.Line,
		Active:      true,
		LoginAt:     ts,
	}
	if err := s.store.CreateAccessEvent(rec); err != nil {
		s.logger.Warn("access event: store failed", zap.Error(err))
		return
	}
	// Info level (not Warn) so the log stays a clean single line — zap attaches a
	// stack trace to Warn/Error entries, which looked noisy next to the other logs.
	s.logger.Info("External access detected",
		zap.String("machine", machine.Name), zap.String("protocol", ev.Protocol),
		zap.String("os_user", ev.OSUser), zap.String("source_ip", ev.SourceIP))

	// Email alerting is disabled for now — detection/history/UI still record the event.
	// To re-enable, restore the SendIntrusionAlert call below.
	//
	// if !ev.Seed && len(machine.NotifyEmails) > 0 {
	// 	if err := s.email.SendIntrusionAlert(machine.NotifyEmails, machine.Name, ev.Protocol, ev.OSUser, ev.SourceIP, ts); err != nil {
	// 		s.logger.Warn("access event: alert email failed", zap.Error(err))
	// 	}
	// }
}

// SetRDPHandler wires the RDP tunnel manager so "rdp_" session output is routed to it.
func (s *AgentServer) SetRDPHandler(h RDPDataHandler) {
	s.rdpHandler = h
}

// SetRemoteControlHandler wires the remote-control manager so "rc_" session
// output — the consent/state replies from the agent — is routed to it. It
// reuses RDPDataHandler because the shape is identical: a session id and a
// blob of bytes.
func (s *AgentServer) SetRemoteControlHandler(h RDPDataHandler) {
	s.rcHandler = h
}

func (s *AgentServer) Register(ctx context.Context, req *agentv1.RegisterRequest) (*agentv1.RegisterResponse, error) {
	s.logger.Info("Register request", zap.String("token", req.Token), zap.String("hostname", req.Hostname))

	// Find pending machine by registration token
	pendingMachine, err := s.store.GetMachineByRegistrationToken(req.Token)
	if err != nil || pendingMachine == nil {
		s.logger.Error("Invalid or expired registration token", zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "invalid or expired registration token")
	}

	// Machine was created through vsay-auth, owner info is already stored
	s.logger.Info("Found pending machine, activating",
		zap.String("name", pendingMachine.Name),
		zap.String("owner_id", pendingMachine.OwnerID.Hex()))

	// Generate AgentID based on tenant + registration_token (first 8 chars for readability)
	tokenShort := req.Token
	if len(tokenShort) > 8 {
		tokenShort = tokenShort[:8]
	}
	// Use tenant_id from pending machine (set by vsay-auth during creation)
	agentID := fmt.Sprintf("%s-%s", pendingMachine.TenantID, tokenShort)

	// Choose initial status: if machine has a custom init script, hold in
	// "executing_script" until the agent reports completion via StatusUpdate.
	initialStatus := "online"
	if pendingMachine.CustomScript != "" {
		initialStatus = "executing_script"
	}

	// Activate the pending machine
	if err := s.store.ActivateMachine(req.Token, agentID, req.OsInfo, req.IpAddress, req.Metadata, initialStatus); err != nil {
		s.logger.Error("Failed to activate machine", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to activate machine")
	}

	s.logger.Info("Machine activated successfully",
		zap.String("agent_id", agentID),
		zap.String("name", pendingMachine.Name))

	return &agentv1.RegisterResponse{
		AgentId:  agentID,
		Approved: true,
		Message:  fmt.Sprintf("Machine '%s' activated successfully", pendingMachine.Name),
		Restrictions: &agentv1.CommandRestrictions{
			AllowedCommands:     []string{"*"},
			SudoAllowedCommands: []string{"*"},
		},
	}, nil
}

func (s *AgentServer) Heartbeat(ctx context.Context, req *agentv1.HeartbeatRequest) (*agentv1.HeartbeatResponse, error) {
	stats := store.ResourceStats{}
	if req.Stats != nil {
		stats = store.ResourceStats{
			CPUPercent:      float64(req.Stats.CpuPercent),
			MemoryPercent:   float64(req.Stats.MemoryPercent),
			DiskPercent:     float64(req.Stats.DiskPercent),
			NetworkInbound:  float64(req.Stats.NetworkInbound),
			NetworkOutbound: float64(req.Stats.NetworkOutbound),
			Uptime:          req.Stats.UptimeSeconds,
		}
	}
	if err := s.store.UpdateMachineHeartbeat(req.AgentId, time.Now(), stats); err != nil {
		s.logger.Warn("heartbeat: store update failed", zap.String("agent_id", req.AgentId), zap.Error(err))
	}
	return &agentv1.HeartbeatResponse{Acknowledged: true}, nil
}

func (s *AgentServer) Stream(stream agentv1.AgentService_StreamServer) error {
	// Wait for first message to identify agent
	firstMsg, err := stream.Recv()
	if err != nil {
		return err
	}

	agentID := firstMsg.AgentId
	if agentID == "" {
		return status.Error(codes.InvalidArgument, "agent_id required in first message")
	}

	// Verify the claimed agentID exists in the database and is not revoked.
	// A holder of any valid mTLS cert could otherwise claim an arbitrary agentID
	// and receive commands/logs meant for a different machine.
	machine, machineErr := s.store.GetMachineByAgentID(agentID)
	if machineErr != nil || machine == nil {
		s.logger.Warn("Stream rejected: unknown agent_id", zap.String("agent_id", agentID))
		return status.Error(codes.Unauthenticated, "unknown agent_id — register first")
	}
	if machine.Revoked {
		s.logger.Warn("Stream rejected: revoked machine", zap.String("agent_id", agentID))
		return status.Error(codes.PermissionDenied, "machine has been revoked")
	}

	s.logger.Info("Agent connected", zap.String("agent_id", agentID))

	conn := s.manager.AddConnection(agentID, stream)
	defer s.manager.RemoveConnection(agentID)

	// If a custom init script is pending, keep status as "executing_script" —
	// it will be flipped to "online" once the agent reports back via StatusUpdate.
	// Otherwise mark online immediately.
	if machineErr == nil && machine.Status == "executing_script" && machine.CustomScript != "" {
		// Send init script to agent after a short delay so the send-loop below
		// has time to start before the message lands in InputChan.
		scriptContent := machine.CustomScript
		go func() {
			time.Sleep(1 * time.Second)
			initMsg := &agentv1.ServerMessage{
				Payload: &agentv1.ServerMessage_Command{
					Command: &agentv1.CommandRequest{
						CommandId: "__vsay_init__",
						Command:   scriptContent,
					},
				},
			}
			select {
			case conn.InputChan <- initMsg:
				s.logger.Info("Init script sent to agent", zap.String("agent_id", agentID))
			default:
				s.logger.Warn("InputChan full, init script dropped", zap.String("agent_id", agentID))
			}
		}()
	} else if err := s.store.UpdateMachineStatus(agentID, "online", time.Now()); err != nil {
		s.logger.Warn("stream: failed to mark machine online", zap.String("agent_id", agentID), zap.Error(err))
	}
	defer s.store.UpdateMachineStatus(agentID, "offline", time.Now())

	// Handle incoming messages from Agent
	go func() {
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				return
			}
			if err != nil {
				s.logger.Error("Stream recv error", zap.Error(err))
				return
			}

			// Process message
			switch payload := msg.Payload.(type) {
			case *agentv1.AgentMessage_Heartbeat:
				stats := store.ResourceStats{}
				if payload.Heartbeat.Stats != nil {
					stats = store.ResourceStats{
						CPUPercent:      float64(payload.Heartbeat.Stats.CpuPercent),
						MemoryPercent:   float64(payload.Heartbeat.Stats.MemoryPercent),
						DiskPercent:     float64(payload.Heartbeat.Stats.DiskPercent),
						NetworkInbound:  float64(payload.Heartbeat.Stats.NetworkInbound),
						NetworkOutbound: float64(payload.Heartbeat.Stats.NetworkOutbound),
						Uptime:          payload.Heartbeat.Stats.UptimeSeconds,
					}
				}
				// Single write: status + stats + last_active in one MongoDB round-trip.
				if err := s.store.UpdateMachineHeartbeat(agentID, time.Now(), stats); err != nil {
					s.logger.Warn("stream heartbeat: store update failed", zap.String("agent_id", agentID), zap.Error(err))
				}
				metrics.AgentHeartbeatsTotal.Inc()
			case *agentv1.AgentMessage_CommandOutput:
				// Get command metadata
				cmdMeta := s.manager.GetCommandMetadata(payload.CommandOutput.CommandId)
				if cmdMeta != nil {
					// Get machine info
					machine, err := s.store.GetMachineByAgentID(agentID)
					if err == nil && cmdMeta.IsTerminal {
						// Parse user ID
						userID, _ := primitive.ObjectIDFromHex(cmdMeta.UserID)

						// Log to database - only essential info
						logEntry := &store.LogEntry{
							MachineID: machine.ID,
							UserID:    userID,
							Username:  cmdMeta.Username,
							Command:   cmdMeta.Command,
							Timestamp: cmdMeta.Timestamp,
							Success:   payload.CommandOutput.ExitCode == 0,
						}

						if logErr := s.store.CreateLog(logEntry); logErr != nil {
							s.logger.Error("Failed to create log entry",
								zap.String("command_id", payload.CommandOutput.CommandId),
								zap.String("command", cmdMeta.Command),
								zap.Error(logErr))
						} else {
							s.logger.Info("Command logged to database",
								zap.String("command_id", payload.CommandOutput.CommandId),
								zap.String("command", cmdMeta.Command),
								zap.String("machine_id", machine.ID.Hex()),
								zap.String("user_id", userID.Hex()),
								zap.Bool("success", payload.CommandOutput.ExitCode == 0))
						}
					} else if err != nil {
						s.logger.Error("Failed to get machine for logging",
							zap.String("agent_id", agentID),
							zap.Error(err))
					}

					// Clean up metadata
					s.manager.RemoveCommandMetadata(payload.CommandOutput.CommandId)
				}
			case *agentv1.AgentMessage_Status:
				statusVal := payload.Status.Status
				// Access events and agent-stats have their own handlers — don't dump the
				// raw status JSON for them (agent stats especially would flood the log).
				if statusVal != "__access_event__" && statusVal != "__agent_stats__" &&
					statusVal != "__access_snapshot__" {
					s.logger.Info("Agent status update",
						zap.String("agent_id", agentID),
						zap.String("status", statusVal),
						zap.String("message", payload.Status.Message))
				}
				// Init script completed (success or error) — bring machine online
				if statusVal == "script_complete" || statusVal == "script_error" {
					if err := s.store.UpdateMachineStatus(agentID, "online", time.Now()); err != nil {
						s.logger.Warn("status update: failed to mark machine online", zap.String("agent_id", agentID), zap.Error(err))
					}
				}
				// External SSH/RDP login/logout detected by the agent.
				if statusVal == "__access_event__" {
					go s.handleAccessEvent(agentID, payload.Status.Message)
				}
				// Full session list, sent once when the agent starts, so
				// sessions that ended while it was down get closed.
				if statusVal == "__access_snapshot__" {
					go s.handleAccessSnapshot(agentID, payload.Status.Message)
				}
				// Agent process resource usage (for Agent Monitoring).
				if statusVal == "__agent_stats__" {
					go s.handleAgentStats(agentID, payload.Status.Message)
				}
			case *agentv1.AgentMessage_TerminalOutput:
				// RDP tunnel sessions ("rdp_") carry port-forward data for the
				// remote-desktop bridge, not terminal output — route them there.
				if s.rcHandler != nil && strings.HasPrefix(payload.TerminalOutput.SessionId, "rc_") {
					// Remote-control control channel: consent and state replies.
					s.rcHandler.HandleAgentData(payload.TerminalOutput.SessionId, payload.TerminalOutput.Data)
				} else if s.rdpHandler != nil && strings.HasPrefix(payload.TerminalOutput.SessionId, "rdp_") {
					s.rdpHandler.HandleAgentData(payload.TerminalOutput.SessionId, payload.TerminalOutput.Data)
					continue
				}
				// Forward to Web via WebSocket
				if s.terminalManager != nil {
					if err := s.terminalManager.SendOutput(payload.TerminalOutput.SessionId, payload.TerminalOutput.Data); err != nil {
						s.logger.Error("Failed to send terminal output to WebSocket",
							zap.String("session_id", payload.TerminalOutput.SessionId),
							zap.Error(err))
					}
				}
				s.logger.Debug("Received terminal output",
					zap.String("session_id", payload.TerminalOutput.SessionId),
					zap.Int("len", len(payload.TerminalOutput.Data)))
			}
		}
	}()

	// Send messages FROM Server TO Agent. A single goroutine owns stream.Send (gRPC
	// streams are not safe for concurrent Send), draining both the terminal/command
	// lane (InputChan) and the dedicated remote-desktop lane (DesktopChan).
	for {
		select {
		case msg := <-conn.InputChan:
			if err := stream.Send(msg); err != nil {
				return err
			}
		case msg := <-conn.DesktopChan:
			if err := stream.Send(msg); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}
