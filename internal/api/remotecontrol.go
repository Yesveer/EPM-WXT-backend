package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-agent-backend/internal/grpc"
	"github.com/vsay/vsay-agent-backend/internal/store"
	"github.com/wwt/guac"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

// Remote control is the AnyDesk-style feature: an admin takes over the user's
// LIVE desktop session rather than opening a new one the way RDP does, the
// user watches along, and the whole thing is recorded.
//
// The heavy lifting is in the agent — it runs its own RFB server inside the
// user's session. This manager only orchestrates: it asks the agent to start a
// session, waits for the user to consent, then reuses the existing
// port-forward-over-gRPC tunnel and guacd to get those pixels into a browser.

// Control-channel message types, mirroring wxt-agent/internal/remotecontrol.
const (
	rcMsgStart  = "rc_start"
	rcMsgStop   = "rc_stop"
	rcMsgStatus = "rc_status"
	rcMsgState  = "rc_state"
)

// Session states, mirroring the agent's ipc.State.
const (
	rcStateIdle            = "idle"
	rcStateAwaitingConsent = "awaiting_consent"
	rcStateActive          = "active"
	rcStateDenied          = "denied"
	rcStateTimedOut        = "timed_out"
	rcStateError           = "error"
)

// rcSessionTTL bounds how long a session record survives without an update.
// A machine that goes offline mid-consent would otherwise leave the portal
// showing "waiting for approval" forever.
const rcSessionTTL = 10 * time.Minute

// rcSession is one remote-control session as the backend sees it.
type rcSession struct {
	AgentID   string `json:"agent_id"`
	SessionID string `json:"session_id"`
	State     string `json:"state"`
	Error     string `json:"error,omitempty"`
	Port      int    `json:"-"` // loopback port on the USER's machine; never exposed
	Password  string `json:"-"` // per-session VNC password; never exposed
	Width     int    `json:"width,omitempty"`
	Height    int    `json:"height,omitempty"`
	Viewer    string `json:"viewer,omitempty"`
	AdminName string `json:"admin_name,omitempty"`
	Reason    string `json:"reason,omitempty"`
	ViewOnly  bool   `json:"view_only"`
	// IdleTimeoutMinutes is what the machine is enforcing for this session.
	IdleTimeoutMinutes int       `json:"idle_timeout_minutes,omitempty"`
	StartedAt          time.Time `json:"started_at,omitempty"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// RemoteControlManager tracks one session per agent.
type RemoteControlManager struct {
	am     *grpc.AgentManager
	store  store.Store
	rdp    *RDPManager
	logger *zap.Logger

	mu       sync.RWMutex
	sessions map[string]*rcSession // agentID -> session
}

// NewRemoteControlManager creates the manager. rdp supplies the tunnel and
// guacd plumbing, which remote control reuses wholesale rather than
// duplicating.
func NewRemoteControlManager(am *grpc.AgentManager, st store.Store, rdp *RDPManager, logger *zap.Logger) *RemoteControlManager {
	m := &RemoteControlManager{
		am:       am,
		store:    st,
		rdp:      rdp,
		logger:   logger,
		sessions: make(map[string]*rcSession),
	}
	go m.reap()
	return m
}

// controlSessionID is the gRPC session the control messages ride on. It is
// derived from the agent id so that a reconnecting agent lands on the same
// channel, and prefixed so the gRPC server can route replies back here.
func controlSessionID(agentID string) string { return "rc_" + agentID }

// HandleAgentData consumes an rc_state message from the agent.
func (m *RemoteControlManager) HandleAgentData(sessionID string, data []byte) {
	var msg struct {
		Type      string `json:"type"`
		Event     string `json:"event"`
		State     string `json:"state"`
		SessionID string `json:"session_id"`
		Error     string `json:"error"`
		Port      int    `json:"port"`
		Password  string `json:"password"`
		Width     int    `json:"width"`
		Height    int    `json:"height"`
		Viewer    string `json:"viewer"`
		Message   string `json:"message"`
	}
	if err := json.Unmarshal(data, &msg); err != nil || msg.Type != rcMsgState {
		return
	}

	agentID := trimPrefix(sessionID, "rc_")

	m.mu.Lock()
	defer m.mu.Unlock()

	s := m.sessions[agentID]
	if s == nil {
		s = &rcSession{AgentID: agentID}
		m.sessions[agentID] = s
	}

	if msg.State != "" {
		s.State = msg.State
	}
	if msg.SessionID != "" {
		s.SessionID = msg.SessionID
	}
	// The password only ever arrives once, on the start reply. Later status
	// messages omit it, so never overwrite a good one with an empty string.
	if msg.Password != "" {
		s.Password = msg.Password
	}
	if msg.Port != 0 {
		s.Port = msg.Port
	}
	if msg.Width != 0 {
		s.Width, s.Height = msg.Width, msg.Height
	}
	if msg.Viewer != "" {
		s.Viewer = msg.Viewer
	}
	s.Error = msg.Error
	if s.Error == "" && msg.Message != "" && isFailureState(msg.State) {
		s.Error = msg.Message
	}
	if s.State == rcStateActive && s.StartedAt.IsZero() {
		s.StartedAt = time.Now()
	}
	s.UpdatedAt = time.Now()

	m.logger.Info("Remote-control state",
		zap.String("agent_id", agentID),
		zap.String("state", s.State),
		zap.String("event", msg.Event),
		zap.String("session", s.SessionID))
}

func isFailureState(state string) bool {
	return state == rcStateDenied || state == rcStateTimedOut || state == rcStateError
}

// reap drops sessions nothing has updated in a while, so a machine that
// vanished mid-handshake does not leave the portal stuck on "waiting".
func (m *RemoteControlManager) reap() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-rcSessionTTL)
		m.mu.Lock()
		for id, s := range m.sessions {
			if s.State != rcStateActive && s.UpdatedAt.Before(cutoff) {
				delete(m.sessions, id)
			}
		}
		m.mu.Unlock()
	}
}

func (m *RemoteControlManager) send(agentID string, payload map[string]any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return m.am.SendDesktopInput(agentID, controlSessionID(agentID), data)
}

func (m *RemoteControlManager) get(agentID string) *rcSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if s := m.sessions[agentID]; s != nil {
		cp := *s
		return &cp
	}
	return nil
}

// ---------------------------------------------------------------- handlers --

// StartRemoteControl asks the machine to begin a session.
//
// POST /api/machines/:agent_id/remote-control/start
//
// It returns as soon as the request is delivered. The user still has to
// approve on their machine, so the response says "awaiting_consent" and the
// caller polls the status endpoint — the portal shows that wait rather than
// hanging on a request for a minute.
func (h *Handler) StartRemoteControl(c *gin.Context) {
	agentID := c.Param("agent_id")

	if h.remoteControl == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "remote control is not enabled on this server"})
		return
	}
	if !h.agentManager.IsAgentConnected(agentID) {
		c.JSON(http.StatusConflict, gin.H{"error": "the machine is offline"})
		return
	}

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}
	if !h.canAccessMachine(c, machine) {
		c.JSON(http.StatusForbidden, gin.H{"error": "you do not have access to this machine"})
		return
	}

	var body struct {
		Reason            string `json:"reason"`
		ViewOnly          bool   `json:"view_only"`
		ConsentTimeoutSec int    `json:"consent_timeout_sec"`
		// IdleTimeoutMinutes comes from the organisation's session settings,
		// which live in vsay-auth — the portal reads them and passes the value
		// through rather than this service reaching into another store.
		IdleTimeoutMinutes int `json:"idle_timeout_minutes"`
	}
	_ = c.ShouldBindJSON(&body)

	// The name shown in the consent prompt comes from the authenticated
	// identity the gateway injected, never from the request body — the whole
	// point of the prompt is that the user can trust who is asking.
	adminName := c.GetHeader("X-Username")
	if email := c.GetHeader("X-User-Email"); email != "" {
		adminName = fmt.Sprintf("%s (%s)", adminName, email)
	}

	m := h.remoteControl
	m.mu.Lock()
	if s := m.sessions[agentID]; s != nil && (s.State == rcStateActive || s.State == rcStateAwaitingConsent) {
		state := s.State
		m.mu.Unlock()
		c.JSON(http.StatusConflict, gin.H{
			"error": "a remote-control session is already in progress",
			"state": state,
		})
		return
	}
	m.sessions[agentID] = &rcSession{
		AgentID:            agentID,
		State:              rcStateAwaitingConsent,
		AdminName:          adminName,
		Reason:             body.Reason,
		ViewOnly:           body.ViewOnly,
		IdleTimeoutMinutes: body.IdleTimeoutMinutes,
		UpdatedAt:          time.Now(),
	}
	m.mu.Unlock()

	payload := map[string]any{
		"type":       rcMsgStart,
		"admin_name": adminName,
		"reason":     body.Reason,
		"view_only":  body.ViewOnly,
	}
	if body.ConsentTimeoutSec > 0 {
		payload["consent_timeout_sec"] = body.ConsentTimeoutSec
	}
	if body.IdleTimeoutMinutes > 0 {
		payload["idle_timeout_minutes"] = body.IdleTimeoutMinutes
	}

	if err := m.send(agentID, payload); err != nil {
		m.mu.Lock()
		delete(m.sessions, agentID)
		m.mu.Unlock()
		h.logger.Error("Could not ask the machine to start remote control",
			zap.String("agent_id", agentID), zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "could not reach the machine"})
		return
	}

	_ = h.store.CreateAuditLog(&store.AuditLog{
		ActorID:    c.GetHeader("X-User-ID"),
		ActorName:  c.GetHeader("X-Username"),
		ActorRole:  c.GetHeader("X-User-Role"),
		Action:     "remote_control.request",
		Resource:   "machine",
		ResourceID: machine.ID.Hex(),
		Details: map[string]any{
			"machine":              machine.Name,
			"reason":               body.Reason,
			"view_only":            body.ViewOnly,
			"idle_timeout_minutes": body.IdleTimeoutMinutes,
		},
		IPAddress: c.ClientIP(),
		Status:    "success",
		Timestamp: time.Now(),
	})

	h.logger.Info("Remote control requested",
		zap.String("agent_id", agentID),
		zap.String("admin", adminName),
		zap.Bool("view_only", body.ViewOnly))

	c.JSON(http.StatusAccepted, gin.H{
		"state":   rcStateAwaitingConsent,
		"message": "waiting for the user to approve",
	})
}

// RemoteControlStatus reports where the session has got to.
//
// GET /api/machines/:agent_id/remote-control/status
func (h *Handler) RemoteControlStatus(c *gin.Context) {
	agentID := c.Param("agent_id")
	if h.remoteControl == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "remote control is not enabled on this server"})
		return
	}

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}
	if !h.canAccessMachine(c, machine) {
		c.JSON(http.StatusForbidden, gin.H{"error": "you do not have access to this machine"})
		return
	}

	s := h.remoteControl.get(agentID)
	if s == nil {
		c.JSON(http.StatusOK, gin.H{"state": rcStateIdle})
		return
	}
	// Port and Password are json:"-" — the loopback port on someone's laptop
	// and its one-time password are of no use to a browser and should not
	// leave the server.
	c.JSON(http.StatusOK, s)
}

// StopRemoteControl ends the session.
//
// POST /api/machines/:agent_id/remote-control/stop
func (h *Handler) StopRemoteControl(c *gin.Context) {
	agentID := c.Param("agent_id")
	if h.remoteControl == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "remote control is not enabled on this server"})
		return
	}

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}
	if !h.canAccessMachine(c, machine) {
		c.JSON(http.StatusForbidden, gin.H{"error": "you do not have access to this machine"})
		return
	}

	m := h.remoteControl
	// Tell the agent even if we think nothing is running: our view can be
	// stale, and a stop that is a no-op costs nothing while a missed one
	// leaves the user's screen shared.
	if err := m.send(agentID, map[string]any{"type": rcMsgStop}); err != nil {
		h.logger.Warn("Could not tell the machine to stop remote control",
			zap.String("agent_id", agentID), zap.Error(err))
	}

	m.mu.Lock()
	if s := m.sessions[agentID]; s != nil {
		s.State = rcStateIdle
		s.Port = 0
		s.Password = ""
		s.UpdatedAt = time.Now()
	}
	m.mu.Unlock()

	_ = h.store.CreateAuditLog(&store.AuditLog{
		ActorID:    c.GetHeader("X-User-ID"),
		ActorName:  c.GetHeader("X-Username"),
		ActorRole:  c.GetHeader("X-User-Role"),
		Action:     "remote_control.stop",
		Resource:   "machine",
		ResourceID: machine.ID.Hex(),
		Details:    map[string]any{"machine": machine.Name},
		IPAddress:  c.ClientIP(),
		Status:     "success",
		Timestamp:  time.Now(),
	})

	c.JSON(http.StatusOK, gin.H{"state": rcStateIdle})
}

// RemoteControlWebSocket carries the Guacamole stream to the browser.
//
// GET /api/machines/:agent_id/remote-control/ws
//
// By the time this is called the user has already approved and the agent's RFB
// server is listening on its own loopback. All that remains is to tunnel that
// port out and point guacd at it.
func (h *Handler) RemoteControlWebSocket(c *gin.Context) {
	agentID := c.Param("agent_id")

	if h.remoteControl == nil || h.rdpManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "remote control is not enabled on this server"})
		return
	}
	if !h.agentManager.IsAgentConnected(agentID) {
		c.JSON(http.StatusConflict, gin.H{"error": "the machine is offline"})
		return
	}

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}
	if !h.canAccessMachine(c, machine) {
		c.JSON(http.StatusForbidden, gin.H{"error": "you do not have access to this machine"})
		return
	}

	s := h.remoteControl.get(agentID)
	if s == nil || s.State != rcStateActive {
		state := rcStateIdle
		if s != nil {
			state = s.State
		}
		c.JSON(http.StatusConflict, gin.H{
			"error": "no approved remote-control session is ready",
			"state": state,
		})
		return
	}
	if s.Port == 0 {
		// Active but portless means the machine reported the session as
		// running without telling us where its RFB server is — the browser
		// would otherwise see a bare 409 and report "session ended", which
		// says nothing about where the break is.
		h.logger.Error("Remote-control session is active but reported no port",
			zap.String("agent_id", agentID), zap.String("session", s.SessionID))
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "the machine reported an active session but no port to connect to",
			"state": s.State,
		})
		return
	}

	width := c.DefaultQuery("width", strconv.Itoa(maxInt(s.Width, 1280)))
	height := c.DefaultQuery("height", strconv.Itoa(maxInt(s.Height, 800)))
	username := c.GetHeader("X-Username")

	server := guac.NewWebsocketServer(func(r *http.Request) (guac.Tunnel, error) {
		tun, err := h.rdpManager.connectVNCTunnel(agentID, s.SessionID, s.Port, username, s.Password, width, height)
		if err != nil {
			// wwt/guac swallows this error, so it is logged here — otherwise a
			// failed connect shows up in the browser as a bare disconnect.
			h.logger.Error("Remote-control connect failed",
				zap.String("agent_id", agentID), zap.Error(err))
		}
		return tun, err
	})
	server.ServeHTTP(c.Writer, c.Request)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// trimPrefix removes prefix from s when present.
func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

// canAccessMachine reports whether the caller may act on this machine.
//
// It mirrors the ownership/allow-list check the other machine handlers do
// inline, with one addition: company and super admins pass regardless, since
// troubleshooting somebody else's laptop is the entire point of remote
// control.
func (h *Handler) canAccessMachine(c *gin.Context, machine *store.Machine) bool {
	switch c.GetString("role") {
	case "super_admin", "company_admin":
		return true
	}

	userID, _ := primitive.ObjectIDFromHex(c.GetString("user_id"))
	if machine.OwnerID == userID {
		return true
	}
	username := c.GetString("username")
	for _, allowed := range machine.AllowedUsers {
		if allowed == username {
			return true
		}
	}
	return false
}
