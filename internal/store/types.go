package store

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User data comes from vsay-auth service via headers (X-Username, X-User-ID, X-User-Email, etc.)
// No local user collection in backend

type Machine struct {
	ID                primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	AgentID           string             `bson:"agent_id" json:"agent_id"`                     // Set after agent connects
	RegistrationToken string             `bson:"registration_token" json:"registration_token"` // Unique token for registration
	Name              string             `bson:"name" json:"name"`
	Description       string             `bson:"description" json:"description"`
	OS                string             `bson:"os" json:"os"`
	IPAddress         string             `bson:"ip_address" json:"ip_address"`
	Status            string             `bson:"status" json:"status"` // "online", "offline", "pending", "revoked"
	LastActive        time.Time          `bson:"last_active" json:"last_active"`
	Uptime            int64              `bson:"uptime" json:"uptime"` // seconds
	OwnerID           primitive.ObjectID `bson:"owner_id" json:"owner_id"`
	TenantID          string             `bson:"tenant_id" json:"tenant_id"`
	OrgID             string             `bson:"org_id" json:"org_id"`
	GroupIDs          []string           `bson:"group_ids" json:"group_ids"`             // Group IDs this machine belongs to
	AllowedUsers      []string           `bson:"allowed_users" json:"allowed_users"`     // List of usernames allowed to access
	ResourceStats     ResourceStats      `bson:"resource_stats" json:"resource_stats"`
	Metadata           map[string]string  `bson:"metadata" json:"metadata"`
	DeployApplication  bool               `bson:"deploy_application" json:"deploy_application"`
	CustomScript       string             `bson:"custom_script,omitempty" json:"custom_script,omitempty"`

	// Security fields
	Revoked         bool       `bson:"revoked" json:"revoked"`                                   // True = all cert signing rejected + gRPC kicked
	RevokedAt       *time.Time `bson:"revoked_at,omitempty" json:"revoked_at,omitempty"`
	CertFingerprint string     `bson:"cert_fingerprint,omitempty" json:"cert_fingerprint,omitempty"` // SHA-256 of last issued client cert

	// NotifyEmails are alerted when an external (non-vsay) SSH/RDP login is detected on
	// the machine. Collected opportunistically from authorized users who view the machine.
	NotifyEmails []string `bson:"notify_emails,omitempty" json:"notify_emails,omitempty"`

	// AgentStats is the vsay agent PROCESS's own resource usage (latest report), for
	// the portal's Agent Monitoring section. Distinct from ResourceStats (the whole machine).
	AgentStats *AgentStats `bson:"agent_stats,omitempty" json:"agent_stats,omitempty"`

	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}

// AgentStats is the vsay agent process's own resource usage.
type AgentStats struct {
	CPUPercent   float64   `bson:"cpu_percent" json:"cpu_percent"`
	MemoryMB     float64   `bson:"memory_mb" json:"memory_mb"`
	Goroutines   int       `bson:"goroutines" json:"goroutines"`
	UptimeSec    int64     `bson:"uptime_sec" json:"uptime_sec"`
	Version      string    `bson:"version" json:"version"`
	OpenTunnels  int       `bson:"open_tunnels" json:"open_tunnels"`   // forwarded RDP/VNC connections
	OpenSessions int       `bson:"open_sessions" json:"open_sessions"` // active terminal (PTY) sessions
	UpdatedAt    time.Time `bson:"updated_at" json:"updated_at"`
}

// AccessEvent records an EXTERNAL login to the machine (SSH on Linux, RDP/console on
// Windows) — i.e. someone connecting directly, bypassing the vsay portal. The agent
// detects these and reports login/logout so we can alert users and show a history.
type AccessEvent struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	MachineID   primitive.ObjectID `bson:"machine_id" json:"machine_id"`
	AgentID     string             `bson:"agent_id" json:"agent_id"`
	MachineName string             `bson:"machine_name" json:"machine_name"`
	TenantID    string             `bson:"tenant_id" json:"tenant_id"`
	Protocol    string             `bson:"protocol" json:"protocol"` // "ssh" | "rdp" | "console"
	OSUser      string             `bson:"os_user" json:"os_user"`   // the OS account that logged in
	SourceIP    string             `bson:"source_ip" json:"source_ip"`
	Line        string             `bson:"line" json:"line"`       // tty/session id (dedup key with os_user)
	Active      bool               `bson:"active" json:"active"`   // still logged in
	LoginAt     time.Time          `bson:"login_at" json:"login_at"`
	LogoutAt    *time.Time         `bson:"logout_at,omitempty" json:"logout_at,omitempty"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
}

type ResourceStats struct {
	CPUPercent      float64 `bson:"cpu_percent" json:"cpu_percent"`
	MemoryPercent   float64 `bson:"memory_percent" json:"memory_percent"`
	DiskPercent     float64 `bson:"disk_percent" json:"disk_percent"`
	NetworkInbound  float64 `bson:"network_inbound" json:"network_inbound"`    // MB/s
	NetworkOutbound float64 `bson:"network_outbound" json:"network_outbound"`  // MB/s
	Uptime          int64   `bson:"uptime_seconds" json:"uptime_seconds"`      // seconds
}

type LogEntry struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	MachineID primitive.ObjectID `bson:"machine_id" json:"machine_id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"user_id"` // Who executed it
	Username  string             `bson:"username" json:"username"`
	SessionID string             `bson:"session_id" json:"session_id"`
	Command   string             `bson:"command" json:"command"`
	Output    string             `bson:"output,omitempty" json:"output,omitempty"` // Command output/response
	Timestamp time.Time          `bson:"timestamp" json:"timestamp"`
	Success   bool               `bson:"success" json:"success"`
	Source    string             `bson:"source" json:"source"`       // "vscode", "cli", "ui"
	Browser   string             `bson:"browser" json:"browser"`     // User agent / browser info
	OSInfo    string             `bson:"os_info" json:"os_info"`     // Client OS info
	IPAddress string             `bson:"ip_address" json:"ip_address"` // Client IP
}

// Session represents a terminal session
type Session struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	SessionID   string             `bson:"session_id" json:"session_id"`
	MachineID   primitive.ObjectID `bson:"machine_id" json:"machine_id"`
	AgentID     string             `bson:"agent_id" json:"agent_id"`
	UserID      primitive.ObjectID `bson:"user_id" json:"user_id"`
	Username    string             `bson:"username" json:"username"`
	Source      string             `bson:"source" json:"source"`     // "vscode", "cli", "ui"
	Browser     string             `bson:"browser" json:"browser"`   // User agent info
	OSInfo      string             `bson:"os_info" json:"os_info"`   // Client OS
	IPAddress   string             `bson:"ip_address" json:"ip_address"`
	Status      string             `bson:"status" json:"status"`     // "active", "closed"
	CommandCount int               `bson:"command_count" json:"command_count"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	ClosedAt    *time.Time         `bson:"closed_at,omitempty" json:"closed_at,omitempty"`
}

type DashboardStats struct {
	TotalMachines    int `json:"total_machines"`
	ActiveMachines   int `json:"active_machines"`
	InactiveMachines int `json:"inactive_machines"`
	TotalSessions    int `json:"total_sessions"`
}

type ActivityLog struct {
	ID          primitive.ObjectID `json:"id"`
	MachineID   primitive.ObjectID `json:"machine_id"`
	MachineName string             `json:"machine_name"`
	Command     string             `json:"command"`
	Success     bool               `json:"success"`
	Timestamp   time.Time          `json:"timestamp"`
}

// AuditLog records admin and system-level actions (user creation, config changes, etc.)
type AuditLog struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ActorID    string             `bson:"actor_id" json:"actor_id"`
	ActorName  string             `bson:"actor_name" json:"actor_name"`
	ActorRole  string             `bson:"actor_role" json:"actor_role"`
	Action     string             `bson:"action" json:"action"`         // e.g. "user.create", "machine.delete"
	Resource   string             `bson:"resource" json:"resource"`     // e.g. "user", "machine"
	ResourceID string             `bson:"resource_id" json:"resource_id"`
	Details    map[string]any     `bson:"details,omitempty" json:"details,omitempty"`
	IPAddress  string             `bson:"ip_address" json:"ip_address"`
	Status     string             `bson:"status" json:"status"`         // "success", "failure"
	Timestamp  time.Time          `bson:"timestamp" json:"timestamp"`
}

type Issue struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Title       string             `bson:"title" json:"title"`
	Description string             `bson:"description" json:"description"`
	Status      string             `bson:"status" json:"status"` // "open", "in_progress", "closed"
	AuthorID    primitive.ObjectID `bson:"author_id" json:"author_id"`
	AuthorName  string             `bson:"author_name" json:"author_name"`
	Images      []string           `bson:"images" json:"images"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
	FixCount    int                `bson:"fix_count" json:"fix_count"`
}

type Fix struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	IssueID    primitive.ObjectID `bson:"issue_id" json:"issue_id"`
	AuthorID   primitive.ObjectID `bson:"author_id" json:"author_id"`
	AuthorName string             `bson:"author_name" json:"author_name"`
	Content    string             `bson:"content" json:"content"`
	Images     []string           `bson:"images" json:"images"`
	Likes      int                `bson:"likes" json:"likes"`
	LikedBy    []string           `bson:"liked_by" json:"liked_by"` // Array of usernames
	IsAccepted bool               `bson:"is_accepted" json:"is_accepted"`
	CreatedAt  time.Time          `bson:"created_at" json:"created_at"`
}

// S3Config holds S3-compatible storage configuration per tenant
type S3Config struct {
	Enabled   bool   `bson:"enabled" json:"enabled"`
	Endpoint  string `bson:"endpoint" json:"endpoint"`   // e.g. "s3.amazonaws.com" or "minio.host:9000"
	Protocol  string `bson:"protocol" json:"protocol"`   // "http" or "https"
	AccessKey string `bson:"access_key" json:"access_key"`
	SecretKey string `bson:"secret_key" json:"secret_key"`
	Bucket    string `bson:"bucket" json:"bucket"`
	Region    string `bson:"region" json:"region"` // AWS region or "" for custom endpoints
}

// LogManagementConfig holds global log retention and archival settings (single document, no tenantID).
type LogManagementConfig struct {
	ID               primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	RetentionDays    int                `bson:"retention_days" json:"retention_days"`       // 0 = never auto-delete
	ArchiveEnabled   bool               `bson:"archive_enabled" json:"archive_enabled"`
	ArchiveEveryDays int                `bson:"archive_every_days" json:"archive_every_days"` // 10, 20, 30
	StorageType      string             `bson:"storage_type" json:"storage_type"`           // "s3","gcs","azure","sftp","nfs","elasticsearch","siem",""
	StorageCredsEnc  []byte             `bson:"storage_creds_enc,omitempty" json:"-"`       // AES-GCM encrypted JSON
	LastArchiveAt    *time.Time         `bson:"last_archive_at,omitempty" json:"last_archive_at,omitempty"`
	NextArchiveAt    *time.Time         `bson:"next_archive_at,omitempty" json:"next_archive_at,omitempty"`
	UpdatedAt        time.Time          `bson:"updated_at" json:"updated_at"`
}

// ArchiveRun tracks a single log archival job execution.
type ArchiveRun struct {
	ID               primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	StartedAt        time.Time          `bson:"started_at" json:"started_at"`
	FinishedAt       *time.Time         `bson:"finished_at,omitempty" json:"finished_at,omitempty"`
	Status           string             `bson:"status" json:"status"`           // "running","success","failed","partial"
	StorageType      string             `bson:"storage_type" json:"storage_type"`
	Trigger          string             `bson:"trigger" json:"trigger"`         // "auto","manual"
	LogsArchived     int64              `bson:"logs_archived" json:"logs_archived"`
	SessionsArchived int64              `bson:"sessions_archived" json:"sessions_archived"`
	LogsDeleted      int64              `bson:"logs_deleted" json:"logs_deleted"`
	BytesArchived    int64              `bson:"bytes_archived" json:"bytes_archived"`
	ArchiveKey       string             `bson:"archive_key" json:"archive_key"`
	ErrorMsg         string             `bson:"error_msg,omitempty" json:"error_msg,omitempty"`
}

// TenantConfig holds per-tenant settings stored in agent-backend
type TenantConfig struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	TenantID  string             `bson:"tenant_id" json:"tenant_id"`
	S3        S3Config           `bson:"s3" json:"s3"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
}

// SessionRecording tracks a terminal session recording stored in S3
type SessionRecording struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	SessionID   string             `bson:"session_id" json:"session_id"`
	MachineID   primitive.ObjectID `bson:"machine_id" json:"machine_id"`
	MachineName string             `bson:"machine_name" json:"machine_name"`
	TenantID    string             `bson:"tenant_id" json:"tenant_id"`
	Username    string             `bson:"username" json:"username"`
	S3Key       string             `bson:"s3_key" json:"s3_key"`
	SizeBytes   int64              `bson:"size_bytes" json:"size_bytes"`
	Duration    int64              `bson:"duration_seconds" json:"duration_seconds"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
}

type AccessRequest struct {
	ID                primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	MachineID         primitive.ObjectID `bson:"machine_id" json:"machine_id"`
	MachineName       string             `bson:"machine_name" json:"machine_name"`
	MachineAgentID    string             `bson:"machine_agent_id" json:"machine_agent_id"`
	RequesterID       string             `bson:"requester_id" json:"requester_id"`
	RequesterUsername string             `bson:"requester_username" json:"requester_username"`
	RequesterEmail    string             `bson:"requester_email" json:"requester_email"`
	TenantID          string             `bson:"tenant_id" json:"tenant_id"`
	OwnerID           string             `bson:"owner_id" json:"owner_id"`
	OwnerEmail        string             `bson:"owner_email" json:"owner_email"` // for email notification
	RequestNote       string             `bson:"request_note" json:"request_note"`
	DurationHours     int                `bson:"duration_hours" json:"duration_hours"`
	Status            string             `bson:"status" json:"status"` // "pending","approved","rejected","expired","revoked"
	ApprovedBy        string             `bson:"approved_by,omitempty" json:"approved_by,omitempty"`
	ApprovedAt        *time.Time         `bson:"approved_at,omitempty" json:"approved_at,omitempty"`
	ExpiresAt         *time.Time         `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	RejectedBy        string             `bson:"rejected_by,omitempty" json:"rejected_by,omitempty"`
	RejectComment     string             `bson:"reject_comment,omitempty" json:"reject_comment,omitempty"`
	RevokedBy         string             `bson:"revoked_by,omitempty" json:"revoked_by,omitempty"`
	RevokedAt         *time.Time         `bson:"revoked_at,omitempty" json:"revoked_at,omitempty"`
	RequestedAt       time.Time          `bson:"requested_at" json:"requested_at"`
	UpdatedAt         time.Time          `bson:"updated_at" json:"updated_at"`
}

type Store interface {
	// User management is handled by vsay-auth service
	// All user data comes via headers (X-Username, X-User-ID, X-User-Email, etc.)

	// Machine registration flow
	CreatePendingMachine(machine *Machine) error
	GetMachineByRegistrationToken(token string) (*Machine, error)
	RevokeMachine(machineID primitive.ObjectID) error          // Marks revoked=true; blocks future sign-cert + gRPC
	UpdateCertFingerprint(token, fingerprint string) error     // Stores SHA-256 of last issued agent cert
	GetMachineByName(name string, ownerID primitive.ObjectID) (*Machine, error)
	ActivateMachine(token string, agentID string, osInfo string, ipAddress string, metadata map[string]string, initialStatus string) error

	RegisterMachine(machine *Machine) error
	GetMachineByAgentID(agentID string) (*Machine, error)
	GetMachineByID(machineID primitive.ObjectID) (*Machine, error)
	GetMachinesByOwner(ownerID primitive.ObjectID) ([]*Machine, error)
	GetMachinesSharedWithUser(username string) ([]*Machine, error)
	GetAllMachines() ([]*Machine, error)
	GetMachinesByTenantID(tenantID string) ([]*Machine, error)
	// CountMachinesByStatus returns per-status counts using index-only scans.
	// Use this instead of GetAllMachines() when you only need counts.
	CountMachinesByStatus() (online, offline, pending int64, err error)
	UpdateMachineStatus(agentID string, status string, lastActive time.Time) error
	UpdateMachineStats(agentID string, stats ResourceStats) error
	// UpdateMachineHeartbeat combines status + stats into a single MongoDB write.
	// Prefer this over calling UpdateMachineStatus + UpdateMachineStats separately.
	UpdateMachineHeartbeat(agentID string, lastActive time.Time, stats ResourceStats) error
	MarkInactiveMachinesOffline(inactiveThreshold time.Duration) error
	// MarkAllMachinesOffline flips every "online" machine to "offline". Called on
	// backend startup: a freshly-started process holds no agent connections, so any
	// lingering "online" status from a previous process is stale. Live agents
	// reconnect within seconds and set themselves back online.
	MarkAllMachinesOffline() error
	DeleteMachine(machineID primitive.ObjectID) error
	GrantMachineAccess(machineID primitive.ObjectID, username string) error
	RevokeMachineAccess(machineID primitive.ObjectID, username string) error
	AddMachineToGroup(agentID string, groupID string) error
	RemoveMachineFromGroup(agentID string, groupID string) error

	CreateLog(log *LogEntry) error
	UpdateLogOutput(logID primitive.ObjectID, output string) error
	GetLogsByMachine(machineID primitive.ObjectID, limit int) ([]*LogEntry, error)
	GetLogsByMachinePaged(machineID primitive.ObjectID, limit, skip int) ([]*LogEntry, error)
	CountLogsByMachine(machineID primitive.ObjectID) (int64, error)
	GetLogsBySession(sessionID string) ([]*LogEntry, error)
	GetLogsBySessionPaged(sessionID string, limit, skip int) ([]*LogEntry, error)
	CountLogsBySession(sessionID string) (int64, error)
	SearchLogsByMachinePaged(machineID primitive.ObjectID, query string, limit, skip int) ([]*LogEntry, int64, error)
	DeleteLogsByMachine(machineID primitive.ObjectID) error

	// Session management
	CreateSession(session *Session) error
	GetSessionByID(sessionID string) (*Session, error)
	GetSessionsByMachine(machineID primitive.ObjectID) ([]*Session, error)
	GetSessionsByMachinePaged(machineID primitive.ObjectID, limit, skip int) ([]*Session, error)
	CountSessionsByMachine(machineID primitive.ObjectID) (int64, error)
	GetActiveSessionsByMachine(machineID primitive.ObjectID) ([]*Session, error)
	GetSessionsByUser(userID primitive.ObjectID) ([]*Session, error)
	UpdateSessionStatus(sessionID string, status string) error
	CloseSession(sessionID string) error
	IncrementSessionCommandCount(sessionID string) error

	GetDashboardStats(ownerID primitive.ObjectID) (*DashboardStats, error)
	GetRecentMachines(ownerID primitive.ObjectID, limit int) ([]*Machine, error)
	GetRecentActivity(ownerID primitive.ObjectID, limit int) ([]*ActivityLog, error)

	// Community/Issues
	CreateIssue(issue *Issue) error
	GetIssueByID(issueID primitive.ObjectID) (*Issue, error)
	GetAllIssues(limit, skip int) ([]*Issue, error)
	UpdateIssue(issueID primitive.ObjectID, updates map[string]interface{}) error
	DeleteIssue(issueID primitive.ObjectID) error
	IncrementIssueFixCount(issueID primitive.ObjectID) error

	// Fixes
	CreateFix(fix *Fix) error
	GetFixesByIssue(issueID primitive.ObjectID) ([]*Fix, error)
	GetFixByID(fixID primitive.ObjectID) (*Fix, error)
	UpdateFix(fixID primitive.ObjectID, updates map[string]interface{}) error
	DeleteFix(fixID primitive.ObjectID) error
	LikeFix(fixID primitive.ObjectID, username string) error
	UnlikeFix(fixID primitive.ObjectID, username string) error
	MarkFixAsAccepted(fixID primitive.ObjectID, issueID primitive.ObjectID) error

	// Tenant configuration (S3, etc.)
	GetTenantConfig(tenantID string) (*TenantConfig, error)
	UpsertTenantConfig(config *TenantConfig) error

	// Session recordings
	CreateRecording(recording *SessionRecording) error
	GetRecordingsByMachine(machineID primitive.ObjectID, limit, skip int) ([]*SessionRecording, error)
	CountRecordingsByMachine(machineID primitive.ObjectID) (int64, error)
	GetRecordingByID(id primitive.ObjectID) (*SessionRecording, error)

	// Log management configuration + archival
	GetLogManagementConfig() (*LogManagementConfig, error)
	UpsertLogManagementConfig(cfg *LogManagementConfig) error
	GetLogsOlderThan(before time.Time, limit int) ([]*LogEntry, error)
	DeleteLogsByIDs(ids []primitive.ObjectID) (int64, error)
	GetSessionsOlderThan(before time.Time, limit int) ([]*Session, error)
	DeleteSessionsByIDs(ids []primitive.ObjectID) (int64, error)
	GetAuditLogsOlderThan(before time.Time, limit int) ([]*AuditLog, error)
	DeleteAuditLogsByIDs(ids []primitive.ObjectID) (int64, error)
	CreateAuditLog(log *AuditLog) error
	CreateArchiveRun(run *ArchiveRun) error
	GetArchiveRuns(limit int) ([]*ArchiveRun, error)
	GetArchiveRunByID(id primitive.ObjectID) (*ArchiveRun, error)
	UpdateArchiveRunFinished(id primitive.ObjectID, status, errMsg string, logsArchived, sessionsArchived, logsDeleted, bytesArchived int64) error

	// Access requests
	CreateAccessRequest(req *AccessRequest) error
	GetAccessRequestsByMachine(machineID primitive.ObjectID) ([]*AccessRequest, error)
	GetAccessRequestsByRequester(requesterID, tenantID string) ([]*AccessRequest, error)
	GetAccessRequestByID(id primitive.ObjectID) (*AccessRequest, error)
	UpdateAccessRequest(req *AccessRequest) error
	GetExpiredAccessRequests() ([]*AccessRequest, error)
	// GetAccessRequestsFiltered powers the admin-facing Access Requests page: one
	// status tab at a time (pending/approved/expired/rejected/revoked), optionally
	// scoped to a tenant and text-searched across requester/machine fields.
	GetAccessRequestsFiltered(tenantID, status, search string, limit, skip int) ([]*AccessRequest, int64, error)

	// External access events (SSH/RDP intrusion tracking)
	CreateAccessEvent(ev *AccessEvent) error
	CloseAccessEvent(agentID, osUser, line string, logoutAt time.Time) error
	GetActiveAccessEvents(machineID primitive.ObjectID) ([]*AccessEvent, error)
	GetAccessEventsByMachine(machineID primitive.ObjectID, limit, skip int) ([]*AccessEvent, error)
	CountAccessEventsByMachine(machineID primitive.ObjectID) (int64, error)
	AddMachineNotifyEmail(machineID primitive.ObjectID, email string) error

	// Agent process stats (Agent Monitoring)
	UpsertAgentStats(agentID string, stats *AgentStats) error

	// Health / readiness
	Ping(ctx context.Context) error
}
