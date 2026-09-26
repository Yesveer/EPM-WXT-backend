package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-agent-backend/internal/grpc"
	s3client "github.com/vsay/vsay-agent-backend/internal/s3"
	"github.com/vsay/vsay-agent-backend/internal/store"
	"github.com/wwt/guac"
	"go.uber.org/zap"
)

// Remote-desktop ports on the target machine. The agent dials 127.0.0.1:<port>
// locally — never exposed to the network, only tunneled over the mTLS gRPC stream.
const (
	rdpRemotePort = 3389 // Windows RDP (Pro/Enterprise)
	vncRemotePort = 5900 // VNC (Windows Home, or Linux desktops)

	// Concurrent desktop-session caps per machine.
	//   Windows Home (VNC): a single shared session.
	//   Windows Pro/Enterprise (RDP): up to 3.
	maxVNCSessions = 1
	maxRDPSessions = 3
)

// portMsg mirrors the agent-side port-forward control message
// (vsay-agent/internal/portforward). We drive that same primitive from the backend
// to carry raw RDP TCP through the existing gRPC stream — no new agent code needed.
type portMsg struct {
	Type         string `json:"type"`
	ConnectionID string `json:"connection_id"`
	RemotePort   int    `json:"remote_port,omitempty"`
	Data         string `json:"data,omitempty"`
	Error        string `json:"error,omitempty"`
}

// rdpTunnel is one browser↔Windows RDP session. It bridges a guacd TCP connection
// to the agent's port-forward channel (which dials Windows localhost:3389).
type rdpTunnel struct {
	sessionID    string
	connectionID string
	agentID      string
	username     string    // account/portal user this session connected as
	protocol     string    // "rdp" or "vnc"
	startedAt    time.Time // when the tunnel opened
	listener     net.Listener
	guacdConn    net.Conn
	// pending buffers agent→guacd bytes that arrive BEFORE guacd connects to the
	// bridge. VNC/RDP servers speak first (e.g. the "RFB 003.008\n" version), so the
	// target's opening bytes often arrive before guacd is attached — without this
	// buffer they'd be dropped and guacd would hang → "Unable to connect".
	pending   [][]byte
	fromAgent int64 // bytes relayed agent→guacd (the target's replies); atomic
	connMu    sync.Mutex
	mgr       *RDPManager
	closeOnce sync.Once
}

// RDPManager tunnels guacd RDP connections to Windows machines through the agent's
// port-forward-over-gRPC primitive. guacd translates RDP ↔ the Guacamole protocol
// the browser canvas speaks; this manager only moves the raw RDP bytes.
type RDPManager struct {
	am          *grpc.AgentManager
	store       store.Store
	logger      *zap.Logger
	tunnels     map[string]*rdpTunnel // sessionID -> tunnel
	mu          sync.RWMutex
	guacdAddr   string // where guacd listens, e.g. 127.0.0.1:4822
	hostGateway string // how guacd reaches this backend's listeners, e.g. host.docker.internal

	// Session recording (best-effort). guacd records the Guacamole stream to a file
	// inside its container; on session end we run guacenc (in the container) to make an
	// .m4v, copy it out with `docker cp`, and upload it to S3 as a SessionRecording.
	recordingEnabled bool
	guacdContainer   string // docker container name of guacd
	recordingDir     string // path INSIDE the guacd container for recordings
}

func NewRDPManager(am *grpc.AgentManager, st store.Store, logger *zap.Logger) *RDPManager {
	guacdAddr := os.Getenv("GUACD_ADDR")
	if guacdAddr == "" {
		guacdAddr = "127.0.0.1:4822"
	}
	hostGateway := os.Getenv("GUACD_HOST_GATEWAY")
	if hostGateway == "" {
		// guacd runs in Docker; this resolves to the host from inside the container.
		hostGateway = "host.docker.internal"
	}
	guacdContainer := os.Getenv("GUACD_CONTAINER")
	if guacdContainer == "" {
		guacdContainer = "vsay-guacd"
	}
	return &RDPManager{
		am:               am,
		store:            st,
		logger:           logger,
		tunnels:          make(map[string]*rdpTunnel),
		guacdAddr:        guacdAddr,
		hostGateway:      hostGateway,
		recordingEnabled: os.Getenv("RDP_RECORDING") != "0", // on by default; best-effort
		guacdContainer:   guacdContainer,
		// Under /tmp: the guacd container runs as a non-root user that cannot create a
		// directory at the container root, so recording-path=/guac-recordings silently
		// failed (create-recording-path couldn't make it) and no file was written. /tmp
		// is world-writable, so guacd can create+write the recording there.
		recordingDir: "/tmp/guac-recordings",
	}
}

// HandleAgentData routes a port-forward message that came back from the agent (as a
// TerminalOutput for an "rdp_" session) to its tunnel. Called by the gRPC server.
func (m *RDPManager) HandleAgentData(sessionID string, data []byte) {
	m.mu.RLock()
	t, ok := m.tunnels[sessionID]
	m.mu.RUnlock()
	if !ok {
		return
	}

	var msg portMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	switch msg.Type {
	case "port_data":
		raw, err := base64.StdEncoding.DecodeString(msg.Data)
		if err != nil {
			return
		}
		// Write under the lock (preserves ordering). If guacd hasn't attached yet,
		// buffer the bytes so the target's opening handshake isn't lost.
		atomic.AddInt64(&t.fromAgent, int64(len(raw)))
		t.connMu.Lock()
		if t.guacdConn != nil {
			_, _ = t.guacdConn.Write(raw)
		} else {
			t.pending = append(t.pending, raw)
		}
		t.connMu.Unlock()
	case "port_closed", "port_error":
		m.logger.Warn("RDP tunnel: agent closed the target connection",
			zap.String("session", sessionID),
			zap.String("reason", msg.Type),
			zap.String("err", msg.Error),
			zap.Int64("bytes_agent_to_guacd", atomic.LoadInt64(&t.fromAgent)))
		t.close()
	}
}

// openTunnel creates a localhost TCP listener for guacd and tells the agent to dial
// 127.0.0.1:<remotePort> (3389 for RDP, 5900 for VNC), relaying it over the gRPC
// stream. Returns the listener port.
//
// maxSessions caps concurrent desktop sessions per machine (VNC=1 on Windows Home,
// RDP=3 on Pro/Enterprise). The count-and-register is done atomically under m.mu so
// two simultaneous connects can't both slip past the limit.
func (m *RDPManager) openTunnel(agentID string, remotePort, maxSessions int) (*rdpTunnel, error) {
	if !m.am.IsAgentConnected(agentID) {
		return nil, fmt.Errorf("agent not connected")
	}

	// Bind on all interfaces (not just loopback) so guacd — which runs in a Docker
	// container and reaches back via host.docker.internal — can connect to this
	// bridge. A loopback-only listener is unreachable from the container. The port is
	// ephemeral and the tunnel is short-lived (one desktop session).
	ln, err := net.Listen("tcp", "0.0.0.0:0") // #nosec G102 -- must be reachable from the guacd Docker container, see comment above
	if err != nil {
		return nil, fmt.Errorf("open rdp listener: %w", err)
	}

	t := &rdpTunnel{
		sessionID: "rdp_" + randomHex(12),
		// Unique per tunnel. The agent's port-forward manager keys connections by this
		// ID GLOBALLY (not per session), so a hardcoded "c1" made a reconnecting session
		// collide with the previous one still tearing down → "Connection not found for
		// data" and misrouted bytes. A unique ID also lets the 3 concurrent RDP sessions
		// actually coexist.
		connectionID: "c_" + randomHex(6),
		agentID:      agentID,
		startedAt:    time.Now(),
		listener:     ln,
		mgr:          m,
	}

	// A Windows client OS allows only ONE interactive session. If two browser tunnels
	// reach the same machine (StrictMode double-mount, duplicate tabs, a reconnect), the
	// new RDP login KICKS the old one ("Disconnected by other connection") and the
	// desktop never finishes painting → black screen churn. So enforce a single live
	// tunnel per agent: newest wins, and we cleanly tear down any prior tunnels for this
	// agent instead of letting them fight on the Windows side.
	_ = maxSessions // single-session enforced below regardless of the old per-protocol cap
	m.mu.Lock()
	var stale []*rdpTunnel
	for _, existing := range m.tunnels {
		if existing.agentID == agentID {
			stale = append(stale, existing)
		}
	}
	m.tunnels[t.sessionID] = t
	m.mu.Unlock()
	for _, old := range stale {
		old.close()
	}

	if err := m.sendToAgent(agentID, t.sessionID, portMsg{
		Type:         "port_connect",
		ConnectionID: t.connectionID,
		RemotePort:   remotePort,
	}); err != nil {
		t.close()
		return nil, fmt.Errorf("send port_connect: %w", err)
	}

	go t.acceptGuacd()
	return t, nil
}

func (t *rdpTunnel) port() int {
	return t.listener.Addr().(*net.TCPAddr).Port
}

// acceptGuacd waits for guacd's single TCP connection, then pumps guacd→agent bytes.
func (t *rdpTunnel) acceptGuacd() {
	conn, err := t.listener.Accept()
	if err != nil {
		t.mgr.logger.Warn("RDP bridge: guacd never connected", zap.String("session", t.sessionID), zap.Error(err))
		return
	}
	// Attach guacd and flush any bytes the target sent before guacd arrived (VNC/RDP
	// servers speak first, so these opening bytes are common and must not be lost).
	t.connMu.Lock()
	t.guacdConn = conn
	pending := t.pending
	t.pending = nil
	t.connMu.Unlock()
	_ = t.listener.Close() // one guacd connection per tunnel
	var flushed int
	for _, b := range pending {
		if _, werr := conn.Write(b); werr != nil {
			break
		}
		flushed += len(b)
	}
	t.mgr.logger.Info("RDP bridge: guacd connected",
		zap.String("session", t.sessionID), zap.String("from", conn.RemoteAddr().String()),
		zap.Int("flushed_pending_bytes", flushed))

	var total int64
	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			total += int64(n)
			if serr := t.mgr.sendToAgent(t.agentID, t.sessionID, portMsg{
				Type:         "port_data",
				ConnectionID: t.connectionID,
				Data:         base64.StdEncoding.EncodeToString(buf[:n]),
			}); serr != nil {
				t.close()
				return
			}
		}
		if err != nil {
			t.mgr.logger.Info("RDP bridge: guacd→agent stream ended",
				zap.String("session", t.sessionID), zap.Int64("bytes_guacd_to_agent", total), zap.Error(err))
			t.close()
			return
		}
	}
}

func (t *rdpTunnel) close() {
	t.closeOnce.Do(func() {
		_ = t.listener.Close()
		t.connMu.Lock()
		if t.guacdConn != nil {
			_ = t.guacdConn.Close()
		}
		t.connMu.Unlock()
		// Tell the agent to drop its Windows:3389 connection.
		_ = t.mgr.sendToAgent(t.agentID, t.sessionID, portMsg{
			Type:         "port_close",
			ConnectionID: t.connectionID,
		})
		t.mgr.mu.Lock()
		delete(t.mgr.tunnels, t.sessionID)
		t.mgr.mu.Unlock()

		// Encode + upload the session recording (best-effort, off the hot path).
		if t.mgr.recordingEnabled {
			go t.mgr.encodeAndUpload(t.sessionID, t.agentID, t.username, t.startedAt)
		}
	})
}

// encodeAndUpload turns the guacd session recording into an .m4v and stores it in S3
// as a SessionRecording (so it shows in the machine's recordings list). Entirely
// best-effort — any failure is logged and the desktop session is unaffected.
//
// Pipeline: guacenc (inside the guacd container) → docker cp the .m4v to a temp file →
// upload to the tenant's S3 → CreateRecording. Requires the `docker` CLI on the host
// and guacenc in the guacd image (it ships with guacamole/guacd).
func (m *RDPManager) encodeAndUpload(sessionID, agentID, username string, startedAt time.Time) {
	log := m.logger.With(zap.String("session", sessionID))

	// Give guacd a moment to finish flushing/closing the recording file.
	time.Sleep(2 * time.Second)

	machine, err := m.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		log.Warn("recording: machine lookup failed", zap.Error(err))
		return
	}
	tenantCfg, err := m.store.GetTenantConfig(machine.TenantID)
	if err != nil || tenantCfg == nil || !tenantCfg.S3.Enabled {
		log.Info("recording: S3 not configured for tenant — skipping", zap.String("tenant", machine.TenantID))
		return
	}

	recFile := m.recordingDir + "/" + sessionID // guac recording path (guacd's view)

	// run always launches a literal "docker" (never a variable command) with args
	// built from server config (m.guacdContainer) and a server-generated random
	// sessionID — never from request/user input — and exec.Command never invokes
	// a shell, so there's no injection surface despite the taint warning below.
	run := func(name string, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		out, e := exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204
		if e != nil {
			log.Warn("recording: command failed", zap.String("cmd", name+" "+strings.Join(args, " ")),
				zap.Error(e), zap.ByteString("out", out))
		}
		return e
	}

	// We do NOT run guacenc — the guacd image doesn't ship it. We store the RAW
	// Guacamole recording and replay it in the browser with Guacamole's own
	// SessionRecording player (looks just like video). Two deployment modes:
	//   • all-in-one image  → guacd + backend share a filesystem, so read recFile directly.
	//   • separate guacd container → copy the file out with `docker cp`.
	var data []byte
	if fi, statErr := os.Stat(recFile); statErr == nil && fi.Size() > 0 {
		d, rerr := os.ReadFile(recFile) // #nosec G304 -- recFile is server config dir + a server-generated random sessionID, not user input
		if rerr != nil || len(d) == 0 {
			log.Warn("recording: could not read local recording file", zap.Error(rerr))
			return
		}
		data = d
		defer os.Remove(recFile)
	} else {
		hostRec := os.TempDir() + "/vsay-rec-" + sessionID + ".guac"
		if err := run("docker", "cp", m.guacdContainer+":"+recFile, hostRec); err != nil {
			return
		}
		defer os.Remove(hostRec)
		defer run("docker", "exec", m.guacdContainer, "rm", "-f", recFile)
		d, rerr := os.ReadFile(hostRec) // #nosec G304 -- hostRec is os.TempDir() + a server-generated random sessionID, not user input
		if rerr != nil || len(d) == 0 {
			log.Warn("recording: could not read recording file", zap.Error(rerr))
			return
		}
		data = d
	}

	client, err := s3client.NewClient(tenantCfg.S3.Endpoint, tenantCfg.S3.Protocol,
		tenantCfg.S3.AccessKey, tenantCfg.S3.SecretKey, tenantCfg.S3.Region, tenantCfg.S3.Bucket)
	if err != nil {
		log.Warn("recording: S3 client init failed", zap.Error(err))
		return
	}

	// .guac extension → the portal plays it with the Guacamole SessionRecording player.
	key := fmt.Sprintf("webxterm/%s/%s/%s/%s/videos/desktop.guac",
		machine.TenantID, machine.Name, sessionID, username)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := client.Upload(ctx, key, data, "application/octet-stream"); err != nil {
		log.Warn("recording: S3 upload failed", zap.String("key", key), zap.Error(err))
		return
	}

	rec := &store.SessionRecording{
		SessionID:   sessionID,
		MachineID:   machine.ID,
		MachineName: machine.Name,
		TenantID:    machine.TenantID,
		Username:    username,
		S3Key:       key,
		SizeBytes:   int64(len(data)),
		Duration:    int64(time.Since(startedAt).Seconds()),
	}
	if err := m.store.CreateRecording(rec); err != nil {
		log.Warn("recording: save metadata failed", zap.Error(err))
		return
	}
	log.Info("Desktop session recording uploaded to S3", zap.String("key", key), zap.Int("bytes", len(data)))
}

func (m *RDPManager) sendToAgent(agentID, sessionID string, msg portMsg) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	// Use the dedicated desktop lane: it blocks with backpressure instead of dropping
	// a chunk after 100ms (which, under RDP's heavy bitmap stream, would tear the whole
	// tunnel down). All of this tunnel's messages ride the same channel, preserving the
	// connect→data→close order.
	return m.am.SendDesktopInput(agentID, sessionID, data)
}

// connectTunnel opens an agent tunnel and hands guacd a live RDP/VNC connection to it.
// protocol is "rdp" or "vnc". Returns a guac.Tunnel the WebSocket server relays to the
// browser.
func (m *RDPManager) connectTunnel(agentID, protocol, username, password, domain, width, height string) (guac.Tunnel, error) {
	remotePort := rdpRemotePort
	maxSessions := maxRDPSessions // Windows Pro/Enterprise: up to 3
	if protocol == "vnc" {
		remotePort = vncRemotePort
		maxSessions = maxVNCSessions // Windows Home: single session only
	}

	t, err := m.openTunnel(agentID, remotePort, maxSessions)
	if err != nil {
		return nil, err
	}
	t.username = username
	t.protocol = protocol

	config := guac.NewGuacamoleConfiguration()
	config.Protocol = protocol
	if protocol == "vnc" {
		// VNC authenticates with a password only — no username/domain.
		config.Parameters = map[string]string{
			"hostname": m.hostGateway,
			"port":     strconv.Itoa(t.port()),
			"password": password,
		}
	} else {
		// RDP (Windows Pro/Enterprise). NLA is the default security modern Windows
		// requires; "any" often negotiates a legacy mode the server accepts then drops
		// a few seconds later. ignore-cert skips the self-signed RDP cert prompt.
		// disabling wallpaper/theming/effects makes the session lighter and more stable.
		config.Parameters = map[string]string{
			"hostname": m.hostGateway,
			"port":     strconv.Itoa(t.port()),
			"username": username,
			"password": password,
			// "tls" (not nla/any): FreeRDP 3.x (guacd 1.6.0) fails NLA/CredSSP against
			// Windows 11 with "Server refused connection (wrong security type?)" (guac
			// 519), refused at ~1251 bytes. We disable the NLA REQUIREMENT on the Windows
			// side (UserAuthentication=0, see configure_windows.go) and connect over plain
			// TLS instead — the CredSSP handshake FreeRDP struggles with is skipped, and
			// the tunnel itself is already mTLS-secured.
			"security":    "tls",
			"ignore-cert": "true",
			// Native FreeRDP 3.x GFX path. The RDP Graphics Pipeline (EGFX) on Windows 11
			// needs 32bpp AND its offscreen surfaces — so we do NOT disable caching (that
			// breaks GFX → black screen) and we keep WDDM enabled on the Windows side.
			// display-update resizes in-session (no reconnect churn / "disconnected by
			// other connection").
			"color-depth":              "32",
			"resize-method":            "display-update",
			"enable-wallpaper":         "false",
			"enable-theming":           "false",
			"enable-font-smoothing":    "true",
			"enable-full-window-drag":  "false",
			"enable-menu-animations":   "false",
		}
		if domain != "" {
			config.Parameters["domain"] = domain
		}
	}
	if w, err := strconv.Atoi(width); err == nil && w > 0 {
		config.OptimalScreenWidth = w
	}
	if h, err := strconv.Atoi(height); err == nil && h > 0 {
		config.OptimalScreenHeight = h
	}

	// Session recording (best-effort): guacd writes the Guacamole stream to a file in
	// its container; on close we encode it to .m4v and upload to S3. create-recording-path
	// makes guacd create the dir. Never fails the connection if recording can't start.
	if m.recordingEnabled {
		config.Parameters["recording-path"] = m.recordingDir
		config.Parameters["recording-name"] = t.sessionID
		config.Parameters["create-recording-path"] = "true"
		config.Parameters["recording-include-keys"] = "false"
	}

	addr, err := net.ResolveTCPAddr("tcp", m.guacdAddr)
	if err != nil {
		t.close()
		return nil, fmt.Errorf("resolve guacd addr: %w", err)
	}
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		t.close()
		return nil, fmt.Errorf("dial guacd (is the guacd container running?): %w", err)
	}

	stream := guac.NewStream(conn, guac.SocketTimeout)
	if err := stream.Handshake(config); err != nil {
		_ = conn.Close()
		t.close()
		return nil, fmt.Errorf("guacd handshake: %w", err)
	}

	m.logger.Info("RDP tunnel established",
		zap.String("agent_id", agentID),
		zap.String("session", t.sessionID),
		zap.Int("bridge_port", t.port()))
	return guac.NewSimpleTunnel(stream), nil
}

// RDPWebSocket is the browser-facing endpoint. guacamole-common-js connects here;
// we relay it through guacd → agent tunnel → Windows RDP.
// GET /api/machines/:agent_id/rdp/ws?username=&password=&domain=&width=&height=
func (h *Handler) RDPWebSocket(c *gin.Context) {
	agentID := c.Param("agent_id")

	if h.rdpManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "RDP not enabled on server"})
		return
	}
	if !h.agentManager.IsAgentConnected(agentID) {
		c.JSON(http.StatusConflict, gin.H{"error": "Agent is offline"})
		return
	}

	username := c.Query("username")
	password := c.Query("password")
	domain := c.Query("domain")
	width := c.DefaultQuery("width", "1280")
	height := c.DefaultQuery("height", "800")

	// Protocol comes from the machine's reported capability (rdp on Windows Pro, vnc on
	// Windows Home). Explicit ?protocol= query overrides for testing.
	protocol := c.Query("protocol")
	if protocol == "" {
		protocol = "rdp"
		if machine, err := h.store.GetMachineByAgentID(agentID); err == nil && machine != nil {
			if machine.Metadata != nil && machine.Metadata["remote_desktop"] == "vnc" {
				protocol = "vnc"
			}
		}
	}

	server := guac.NewWebsocketServer(func(r *http.Request) (guac.Tunnel, error) {
		tun, err := h.rdpManager.connectTunnel(agentID, protocol, username, password, domain, width, height)
		if err != nil {
			// wwt/guac swallows this error, so log it here — it's the real reason a
			// desktop connect fails (guacd down, handshake rejected, etc.).
			h.logger.Error("RDP connect failed",
				zap.String("agent_id", agentID), zap.String("protocol", protocol), zap.Error(err))
		}
		return tun, err
	})
	server.ServeHTTP(c.Writer, c.Request)
}

// DesktopSessionInfo describes one live remote-desktop session on a machine.
type DesktopSessionInfo struct {
	SessionID string `json:"session_id"`
	Username  string `json:"username"`
	Protocol  string `json:"protocol"`
	StartedAt string `json:"started_at"`
}

// ActiveSessions returns the live desktop sessions for an agent.
func (m *RDPManager) ActiveSessions(agentID string) []DesktopSessionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []DesktopSessionInfo{}
	for _, t := range m.tunnels {
		if t.agentID != agentID {
			continue
		}
		out = append(out, DesktopSessionInfo{
			SessionID: t.sessionID,
			Username:  t.username,
			Protocol:  t.protocol,
			StartedAt: t.startedAt.UTC().Format(time.RFC3339),
		})
	}
	return out
}

// DesktopSessions lists the live remote-desktop sessions on a machine (who is
// connected right now). GET /api/machines/:agent_id/desktop/sessions
func (h *Handler) DesktopSessions(c *gin.Context) {
	agentID := c.Param("agent_id")
	if h.rdpManager == nil {
		c.JSON(http.StatusOK, gin.H{"sessions": []DesktopSessionInfo{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessions": h.rdpManager.ActiveSessions(agentID)})
}

// RDPFile returns a downloadable .rdp file for launching a NATIVE RDP client
// (Microsoft "Windows App" / Remote Desktop). Native clients render Windows 11's RDP
// graphics pipeline correctly — the exact thing guacd/FreeRDP renders as a black
// screen — so this is the reliable path to a working desktop.
//
// Phase 1: the client connects DIRECTLY to the machine's IP:3389, which works when the
// client and the machine share a network (e.g. a Windows VM in VMware Fusion on the
// same Mac). ?host= overrides the auto-detected address; ?username= overrides the
// account. The client prompts for the machine password at connect time.
// GET /api/machines/:agent_id/rdp/file?username=&host=
func (h *Handler) RDPFile(c *gin.Context) {
	agentID := c.Param("agent_id")
	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}

	host := strings.TrimSpace(c.Query("host"))
	if host == "" {
		host = strings.TrimSpace(machine.IPAddress)
	}
	if host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no reachable address for this machine — pass ?host=<ip>"})
		return
	}

	username := strings.TrimSpace(c.Query("username"))
	if username == "" && machine.Metadata != nil {
		username = machine.Metadata["remote_desktop_user"]
	}

	name := machine.Name
	if name == "" {
		name = agentID
	}

	// Minimal .rdp tuned for our setup: NLA is disabled on the Windows side, the RDP
	// cert is self-signed, and the client should prompt for the machine password.
	var b strings.Builder
	fmt.Fprintf(&b, "full address:s:%s:3389\r\n", host)
	if username != "" {
		fmt.Fprintf(&b, "username:s:%s\r\n", username)
	}
	b.WriteString("prompt for credentials:i:1\r\n")
	b.WriteString("authentication level:i:0\r\n") // don't block on self-signed cert
	b.WriteString("enablecredsspsupport:i:0\r\n")  // NLA disabled server-side
	b.WriteString("screen mode id:i:2\r\n")        // full screen
	b.WriteString("redirectclipboard:i:1\r\n")
	b.WriteString("audiomode:i:0\r\n")

	// Sanitise the filename (drop anything but simple chars).
	safe := strings.Map(func(r rune) rune {
		if r == ' ' || r == '.' || r == '_' || r == '-' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, name)

	c.Header("Content-Type", "application/x-rdp")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.rdp"`, safe))
	c.String(http.StatusOK, b.String())
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "x"
	}
	return hex.EncodeToString(b)
}
