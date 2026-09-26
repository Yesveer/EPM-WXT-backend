package api

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-agent-backend/internal/grpc"
	"github.com/vsay/vsay-agent-backend/internal/store"
	"github.com/vsay/vsay-agent-backend/internal/upload"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

type Handler struct {
	store           store.Store
	agentManager    *grpc.AgentManager
	terminalManager *TerminalManager
	uploadService   *upload.Service
	rdpManager      *RDPManager
	remoteControl   *RemoteControlManager
	logger          *zap.Logger
}

func NewHandler(s store.Store, am *grpc.AgentManager, us *upload.Service, l *zap.Logger) *Handler {
	return &Handler{
		store:           s,
		agentManager:    am,
		terminalManager: NewTerminalManager(l),
		uploadService:   us,
		logger:          l,
	}
}

// GetTerminalManager returns the terminal manager for gRPC integration
func (h *Handler) GetTerminalManager() *TerminalManager {
	return h.terminalManager
}

// SetRDPManager wires the RDP tunnel manager (remote-desktop feature).
// SetRemoteControlManager wires the AnyDesk-style live-session manager.
func (h *Handler) SetRemoteControlManager(rc *RemoteControlManager) {
	h.remoteControl = rc
}

// GetRemoteControlManager exposes the manager so main.go can route the agent's
// rc_ replies to it.
func (h *Handler) GetRemoteControlManager() *RemoteControlManager {
	return h.remoteControl
}

func (h *Handler) SetRDPManager(rm *RDPManager) {
	h.rdpManager = rm
}

// Auth Middleware - validates requests from vsay-auth gateway
// All requests must come through vsay-auth with user context headers
func (h *Handler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// All requests must come from vsay-auth gateway with user context headers
		username := c.GetHeader("X-Username")
		userID := c.GetHeader("X-User-ID")

		// Require user context from vsay-auth
		if username == "" || userID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized - requests must come through vsay-auth gateway",
			})
			return
		}

		// Set user context from vsay-auth headers
		c.Set("user_id", userID)
		c.Set("username", username)
		c.Set("email", c.GetHeader("X-User-Email"))
		c.Set("tenant_id", c.GetHeader("X-Tenant-ID"))
		c.Set("tenant_name", c.GetHeader("X-Tenant-Name"))
		c.Set("role", c.GetHeader("X-User-Role"))
		c.Set("machine_role", c.GetHeader("X-Machine-Role"))
		c.Set("keycloak_id", c.GetHeader("X-Keycloak-ID"))
		c.Set("source", c.GetHeader("X-Source"))

		c.Next()
	}
}

// User authentication is now handled by vsay-auth service
// Signup, Login, and token management endpoints have been removed
// All user authentication must go through vsay-auth gateway

// Machine Routes

// GET /api/machines
func (h *Handler) ListMachines(c *gin.Context) {
	userIDStr := c.GetString("user_id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		// If user_id is not a valid ObjectID, try to get it from the context as string
		// (happens when request comes from vsay-auth with header-based auth)
		userIDStr = c.GetString("user_id")
	}

	// Get username and tenant from context (set by AuthMiddleware from vsay-auth headers)
	username := c.GetString("username")
	tenantID := c.GetString("tenant_id")
	role := c.GetString("role")

	var ownedMachines, sharedMachines []*store.Machine

	// Check if tenant_id query parameter is provided (only for super_admin)
	queryTenantID := c.Query("tenant_id")
	forRequest := c.Query("for_request") == "true"

	if queryTenantID != "" && role == "super_admin" {
		// Super admin viewing specific tenant - get all machines
		tenantID = queryTenantID
		allMachines, err := h.store.GetAllMachines()
		if err != nil {
			h.logger.Error("Failed to fetch all machines", zap.Error(err))
			ownedMachines = []*store.Machine{}
		} else {
			ownedMachines = allMachines
		}
		sharedMachines = []*store.Machine{}
	} else if forRequest && tenantID != "" {
		// Request-access selector: show every machine in the tenant so users can request access
		allTenantMachines, err := h.store.GetMachinesByTenantID(tenantID)
		if err != nil {
			h.logger.Error("Failed to fetch tenant machines", zap.Error(err))
			ownedMachines = []*store.Machine{}
		} else {
			ownedMachines = allTenantMachines
		}
		sharedMachines = []*store.Machine{}
	} else {
		// Regular flow - get owned and shared machines
		ownedMachines, err = h.store.GetMachinesByOwner(userID)
		if err != nil {
			h.logger.Error("Failed to fetch owned machines", zap.Error(err))
			ownedMachines = []*store.Machine{} // Continue with empty list
		}

		// Get shared machines (where user has access)
		sharedMachines, err = h.store.GetMachinesSharedWithUser(username)
		if err != nil {
			h.logger.Error("Failed to fetch shared machines", zap.Error(err))
			sharedMachines = []*store.Machine{} // Continue with empty list
		}
	}

	// Use a map to deduplicate machines by ID (avoid duplicates when user is both owner and in allowed_users)
	machineMap := make(map[string]*store.Machine)

	// Add owned machines first
	for _, machine := range ownedMachines {
		machineMap[machine.ID.Hex()] = machine
	}

	// Add shared machines (won't duplicate if already in map)
	for _, machine := range sharedMachines {
		if _, exists := machineMap[machine.ID.Hex()]; !exists {
			machineMap[machine.ID.Hex()] = machine
		}
	}

	// Filter by tenant_id and optional search query
	searchQuery := strings.ToLower(c.Query("search"))
	filteredMachines := make([]*store.Machine, 0)
	for _, machine := range machineMap {
		if machine.TenantID != tenantID && machine.TenantID != "" && machine.TenantID != userID.Hex() {
			continue
		}
		if searchQuery != "" {
			if !strings.Contains(strings.ToLower(machine.Name), searchQuery) &&
				!strings.Contains(strings.ToLower(machine.Description), searchQuery) {
				continue
			}
		}
		filteredMachines = append(filteredMachines, machine)
	}

	total := len(filteredMachines)

	// If limit param is not provided, return all machines (no pagination)
	limitStr := c.Query("limit")
	if limitStr == "" {
		c.JSON(http.StatusOK, gin.H{
			"machines":    filteredMachines,
			"total":       total,
			"page":        1,
			"limit":       total,
			"total_pages": 1,
		})
		return
	}

	// Server-side pagination (only when limit is explicitly passed)
	listPage, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	listLimit, _ := strconv.Atoi(limitStr)
	if listPage < 1 {
		listPage = 1
	}
	if listLimit < 1 || listLimit > 500 {
		listLimit = 10
	}

	listTotalPages := total / listLimit
	if total%listLimit != 0 {
		listTotalPages++
	}

	start := (listPage - 1) * listLimit
	end := start + listLimit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	c.JSON(http.StatusOK, gin.H{
		"machines":    filteredMachines[start:end],
		"total":       total,
		"page":        listPage,
		"limit":       listLimit,
		"total_pages": listTotalPages,
	})
}

// POST /api/machines - Create a pending machine (returns registration token)
func (h *Handler) CreatePendingMachine(c *gin.Context) {
	var req struct {
		Name              string `json:"name" binding:"required"`
		Description       string `json:"description"`
		DeployApplication bool   `json:"deploy_application"`
		CustomScript      string `json:"custom_script"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)
	tenantID := c.GetString("tenant_id")
	username := c.GetString("username")

	// Check if machine with same name already exists for this user
	existingMachine, err := h.store.GetMachineByName(req.Name, userID)
	if err == nil && existingMachine != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Machine with this name already exists"})
		return
	}

	// Generate cryptographically random registration token (256 bits).
	// MongoDB ObjectID was predictable (timestamp + pid + counter) — crypto/rand is not.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		h.logger.Error("Failed to generate registration token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}
	registrationToken := hex.EncodeToString(tokenBytes)

	// Use registration token as temporary agent_id for pending machines
	// This will be replaced with actual agent_id when machine is activated
	temporaryAgentID := "pending-" + registrationToken

	// Automatically add creator to allowed users
	initialAllowedUsers := []string{}
	if username != "" {
		initialAllowedUsers = append(initialAllowedUsers, username)
	}

	machine := &store.Machine{
		AgentID:           temporaryAgentID,
		RegistrationToken: registrationToken,
		Name:              req.Name,
		Description:       req.Description,
		Status:            "pending",
		OwnerID:           userID,
		TenantID:          tenantID,
		OrgID:             tenantID,
		GroupIDs:          []string{},
		AllowedUsers:      initialAllowedUsers,
		ResourceStats:     store.ResourceStats{},
		Metadata:          make(map[string]string),
		DeployApplication: req.DeployApplication,
		CustomScript:      req.CustomScript,
	}

	if err := h.store.CreatePendingMachine(machine); err != nil {
		h.logger.Error("Failed to create pending machine", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create machine"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":                 machine.ID.Hex(),
		"name":               machine.Name,
		"description":        machine.Description,
		"registration_token": registrationToken,
		"status":             "pending",
	})
}

// POST /api/machines/:agent_id/command
func (h *Handler) ExecuteCommand(c *gin.Context) {
	agentID := c.Param("agent_id")
	var req struct {
		Command string `json:"command" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify ownership or access
	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	// Check if user owns machine or has access
	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)
	username := c.GetString("username")

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
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
		return
	}

	cmdID, err := h.agentManager.SendCommand(agentID, req.Command, nil)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"command_id": cmdID, "status": "sent"})
}

// GET /api/machines/by-id/:machine_id - Get machine by MongoDB ObjectID
func (h *Handler) GetMachineByID(c *gin.Context) {
	machineIDStr := c.Param("machine_id")
	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)

	machineID, err := primitive.ObjectIDFromHex(machineIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid machine ID"})
		return
	}

	machine, err := h.store.GetMachineByID(machineID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	// Get username from context
	username := c.GetString("username")

	// Check if user is owner OR has been granted access
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
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
		return
	}

	// Opportunistically collect this authorized viewer's email as an intrusion-alert
	// recipient for the machine (so external SSH/RDP logins notify everyone who uses it).
	if em := c.GetString("email"); em != "" {
		already := false
		for _, e := range machine.NotifyEmails {
			if e == em {
				already = true
				break
			}
		}
		if !already {
			go h.store.AddMachineNotifyEmail(machine.ID, em)
		}
	}

	// Check if agent is connected (only if machine is not pending)
	isConnected := false
	if machine.AgentID != "" {
		isConnected = h.agentManager.IsAgentConnected(machine.AgentID)
	}

	response := gin.H{
		"id":                 machine.ID.Hex(),
		"agent_id":           machine.AgentID,
		"registration_token": machine.RegistrationToken,
		"name":               machine.Name,
		"description":        machine.Description,
		"os":                 machine.OS,
		"ip_address":         machine.IPAddress,
		"status":             machine.Status,
		"is_connected":       isConnected,
		"last_active":        machine.LastActive,
		"uptime":             machine.Uptime,
		"resource_stats":     machine.ResourceStats,
		"metadata":           machine.Metadata,
		"agent_stats":        machine.AgentStats,
	}

	c.JSON(http.StatusOK, response)
}

// GET /api/machines/:agent_id
func (h *Handler) GetMachineDetails(c *gin.Context) {
	agentID := c.Param("agent_id")
	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	// Get username from context
	username := c.GetString("username")

	// Check if user is owner OR has been granted access
	hasAccess := machine.OwnerID == userID
	if !hasAccess {
		// Check if user is in allowed_users list
		for _, allowedUser := range machine.AllowedUsers {
			if allowedUser == username {
				hasAccess = true
				break
			}
		}
	}

	if !hasAccess {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
		return
	}

	// Check if agent is connected
	isConnected := h.agentManager.IsAgentConnected(agentID)

	response := gin.H{
		"id":             machine.ID.Hex(),
		"agent_id":       machine.AgentID,
		"name":           machine.Name,
		"description":    machine.Description,
		"os":             machine.OS,
		"ip_address":     machine.IPAddress,
		"status":         machine.Status,
		"is_connected":   isConnected,
		"last_active":    machine.LastActive,
		"uptime":         machine.Uptime,
		"resource_stats": machine.ResourceStats,
		"metadata":       machine.Metadata,
	}

	c.JSON(http.StatusOK, response)
}

// GET /api/machines/:agent_id/logs
func (h *Handler) GetMachineLogs(c *gin.Context) {
	agentID := c.Param("agent_id")
	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	// Get username from context
	username := c.GetString("username")

	// Check if user is owner OR has been granted access
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
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 200 {
		limit = 25
	}
	skip := (page - 1) * limit

	total, err := h.store.CountLogsByMachine(machine.ID)
	if err != nil {
		total = 0
	}

	logs, err := h.store.GetLogsByMachinePaged(machine.ID, limit, skip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch logs"})
		return
	}

	// Enrich logs with username and machine name
	type LogResponse struct {
		ID          string    `json:"id"`
		MachineName string    `json:"machine_name"`
		Username    string    `json:"username"`
		Command     string    `json:"command"`
		Success     bool      `json:"success"`
		Timestamp   time.Time `json:"timestamp"`
		SessionID   string    `json:"session_id"`
		Source      string    `json:"source"`
		Browser     string    `json:"browser"`
		OSInfo      string    `json:"os_info"`
		IPAddress   string    `json:"ip_address"`
	}

	enrichedLogs := make([]LogResponse, 0, len(logs))
	for _, log := range logs {
		enrichedLogs = append(enrichedLogs, LogResponse{
			ID:          log.ID.Hex(),
			MachineName: machine.Name,
			Username:    log.Username,
			Command:     log.Command,
			Success:     log.Success,
			Timestamp:   log.Timestamp,
			SessionID:   log.SessionID,
			Source:      log.Source,
			Browser:     log.Browser,
			OSInfo:      log.OSInfo,
			IPAddress:   log.IPAddress,
		})
	}

	totalPages := int(total) / limit
	if int(total)%limit != 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":        enrichedLogs,
		"total":       total,
		"page":        page,
		"limit":       limit,
		"total_pages": totalPages,
	})
}

// GET /api/dashboard/stats
func (h *Handler) GetDashboardStats(c *gin.Context) {
	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)

	// Get dashboard stats
	stats, err := h.store.GetDashboardStats(userID)
	if err != nil {
		h.logger.Error("Failed to get dashboard stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch stats"})
		return
	}

	// Get machines for resource averages
	machines, err := h.store.GetMachinesByOwner(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch stats"})
		return
	}

	var onlineCount, totalCPU, totalMemory, totalDisk, totalNetIn, totalNetOut float64
	for _, m := range machines {
		if m.Status == "online" {
			onlineCount++
			totalCPU += m.ResourceStats.CPUPercent
			totalMemory += m.ResourceStats.MemoryPercent
			totalDisk += m.ResourceStats.DiskPercent
			totalNetIn += m.ResourceStats.NetworkInbound
			totalNetOut += m.ResourceStats.NetworkOutbound
		}
	}

	var avgCPU, avgMemory, avgDisk, avgNetIn, avgNetOut float64
	if onlineCount > 0 {
		avgCPU = totalCPU / onlineCount
		avgMemory = totalMemory / onlineCount
		avgDisk = totalDisk / onlineCount
		avgNetIn = totalNetIn / onlineCount
		avgNetOut = totalNetOut / onlineCount
	}

	c.JSON(http.StatusOK, gin.H{
		"total_machines":    stats.TotalMachines,
		"active_machines":   stats.ActiveMachines,
		"inactive_machines": stats.InactiveMachines,
		"total_sessions":    stats.TotalSessions,
		"avg_cpu":           avgCPU,
		"avg_memory":        avgMemory,
		"avg_disk":          avgDisk,
		"avg_network_in":    avgNetIn,
		"avg_network_out":   avgNetOut,
	})
}

// Profile Routes

// GET /api/profile
// GET /api/profile - returns user info from vsay-auth context
func (h *Handler) GetProfile(c *gin.Context) {
	// All user data comes from vsay-auth headers
	c.JSON(http.StatusOK, gin.H{
		"id":          c.GetString("user_id"),
		"username":    c.GetString("username"),
		"email":       c.GetString("email"),
		"tenant_id":   c.GetString("tenant_id"),
		"tenant_name": c.GetString("tenant_name"),
		"role":        c.GetString("role"),
		"keycloak_id": c.GetString("keycloak_id"),
	})
}

// Profile management endpoints removed - all user management is handled by vsay-auth
// - RegenerateAPIKey: API keys managed by vsay-auth
// - ResetPassword: passwords managed by vsay-auth
// - UploadAvatar: avatar management should be in vsay-auth

// POST /api/auth/refresh
// RefreshToken endpoint removed - token refresh is handled by vsay-auth service

// GET /api/dashboard/recent-machines
func (h *Handler) GetRecentMachines(c *gin.Context) {
	userID := c.MustGet("user_id").(string)
	ownerID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Default limit 5
	limit := 5
	machines, err := h.store.GetRecentMachines(ownerID, limit)
	if err != nil {
		h.logger.Error("Failed to get recent machines", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get recent machines"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"machines": machines})
}

// GET /api/dashboard/recent-activity
func (h *Handler) GetRecentActivity(c *gin.Context) {
	userID := c.MustGet("user_id").(string)
	ownerID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Limit to 5 activities
	limit := 5
	activities, err := h.store.GetRecentActivity(ownerID, limit)
	if err != nil {
		h.logger.Error("Failed to get recent activity", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get recent activity"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"activities": activities})
}

// GET /api/users
// ListUsers endpoint removed - user management is handled by vsay-auth
// Users should be fetched from vsay-auth service, not from backend database

// GET /api/machines/:agent_id/access/users
func (h *Handler) GetMachineAccessUsers(c *gin.Context) {
	agentID := c.Param("agent_id")
	userIDStr := c.GetString("user_id")
	username := c.GetString("username")
	role := c.GetString("role")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)

	// Get machine
	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	// Viewable by the owner, company_admin/super_admin, or anyone who currently
	// has access to the machine — a granted user should be able to see who else
	// has access. Removing someone stays owner-only (enforced in RevokeAccess).
	authorized := machine.OwnerID == userID || role == "company_admin" || role == "super_admin"
	if !authorized {
		for _, allowed := range machine.AllowedUsers {
			if allowed == username {
				authorized = true
				break
			}
		}
	}
	if !authorized {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
		return
	}

	// Get user details for each allowed user
	type AccessUser struct {
		Username  string    `json:"username"`
		Email     string    `json:"email"`
		GrantedAt time.Time `json:"granted_at"`
	}

	accessUsers := make([]AccessUser, 0)
	for _, username := range machine.AllowedUsers {
		// User details (like email) not available from vsay-auth context
		// Only username is stored in allowed_users list
		accessUsers = append(accessUsers, AccessUser{
			Username:  username,
			Email:     "",         // Not available without vsay-auth lookup
			GrantedAt: time.Now(), // TODO: Store grant timestamp
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"users": accessUsers,
		"total": len(accessUsers),
	})
}

// DELETE /api/machines/:agent_id
func (h *Handler) DeleteMachine(c *gin.Context) {
	agentID := c.Param("agent_id")
	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)

	// Get machine
	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	// Verify ownership
	if machine.OwnerID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
		return
	}

	// Revoke first so the agent is blocked from re-signing certs immediately,
	// even during the brief window before the DB delete completes.
	if err := h.store.RevokeMachine(machine.ID); err != nil {
		h.logger.Warn("Failed to revoke machine before delete", zap.Error(err))
		// Non-fatal — continue with delete
	}

	// Kick the live gRPC connection (if agent is connected).
	// The agent's reconnect loop will fail at Register because the token is now revoked.
	if machine.AgentID != "" {
		h.agentManager.KickAgent(machine.AgentID)
	}

	// Delete machine (this also deletes associated logs)
	if err := h.store.DeleteMachine(machine.ID); err != nil {
		h.logger.Error("Failed to delete machine", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete machine"})
		return
	}

	h.logger.Info("Machine deleted and agent kicked",
		zap.String("agent_id", agentID),
		zap.String("machine_id", machine.ID.Hex()),
		zap.String("user_id", userIDStr))

	c.JSON(http.StatusOK, gin.H{"message": "Machine deleted successfully"})
}

// POST /api/machines/:agent_id/access/grant
func (h *Handler) GrantAccess(c *gin.Context) {
	agentID := c.Param("agent_id")
	userIDStr := c.GetString("user_id")
	username := c.GetString("username")

	var req struct {
		Username string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username is required"})
		return
	}

	// Get machine
	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	// Verify ownership (skip for system requests from vsay-auth access service)
	if username != "system" {
		userID, err := primitive.ObjectIDFromHex(userIDStr)
		if err == nil && machine.OwnerID != userID {
			c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
			return
		}
	}

	// Note: User existence is not verified here since vsay-auth manages users
	// If the username doesn't exist, they simply won't be able to access the machine

	// Grant access
	if err := h.store.GrantMachineAccess(machine.ID, req.Username); err != nil {
		h.logger.Error("Failed to grant access", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to grant access"})
		return
	}

	h.logger.Info("Access granted",
		zap.String("machine_id", machine.ID.Hex()),
		zap.String("username", req.Username))

	c.JSON(http.StatusOK, gin.H{"message": "Access granted successfully"})
}

// POST /api/machines/:agent_id/access/revoke
func (h *Handler) RevokeAccess(c *gin.Context) {
	agentID := c.Param("agent_id")
	userIDStr := c.GetString("user_id")
	username := c.GetString("username")

	var req struct {
		Username string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username is required"})
		return
	}

	// Get machine
	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	// Verify ownership (skip for system requests from vsay-auth access service)
	if username != "system" {
		userID, err := primitive.ObjectIDFromHex(userIDStr)
		if err == nil && machine.OwnerID != userID {
			c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
			return
		}
	}

	// Revoke access
	if err := h.store.RevokeMachineAccess(machine.ID, req.Username); err != nil {
		h.logger.Error("Failed to revoke access", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke access"})
		return
	}

	h.logger.Info("Access revoked",
		zap.String("machine_id", machine.ID.Hex()),
		zap.String("username", req.Username))

	c.JSON(http.StatusOK, gin.H{"message": "Access revoked successfully"})
}

// POST /api/machines/:agent_id/groups/add
func (h *Handler) AddMachineToGroup(c *gin.Context) {
	agentID := c.Param("agent_id")
	username := c.GetString("username")

	var req struct {
		GroupID string `json:"group_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Group ID is required"})
		return
	}

	// Verify this is a system request from vsay-auth
	if username != "system" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
		return
	}

	// Add machine to group
	if err := h.store.AddMachineToGroup(agentID, req.GroupID); err != nil {
		h.logger.Error("Failed to add machine to group", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add machine to group"})
		return
	}

	h.logger.Info("Machine added to group",
		zap.String("agent_id", agentID),
		zap.String("group_id", req.GroupID))

	c.JSON(http.StatusOK, gin.H{"message": "Machine added to group successfully"})
}

// POST /api/machines/:agent_id/groups/remove
func (h *Handler) RemoveMachineFromGroup(c *gin.Context) {
	agentID := c.Param("agent_id")
	username := c.GetString("username")

	var req struct {
		GroupID string `json:"group_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Group ID is required"})
		return
	}

	// Verify this is a system request from vsay-auth
	if username != "system" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
		return
	}

	// Remove machine from group
	if err := h.store.RemoveMachineFromGroup(agentID, req.GroupID); err != nil {
		h.logger.Error("Failed to remove machine from group", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove machine from group"})
		return
	}

	h.logger.Info("Machine removed from group",
		zap.String("agent_id", agentID),
		zap.String("group_id", req.GroupID))

	c.JSON(http.StatusOK, gin.H{"message": "Machine removed from group successfully"})
}

// ===== Session API Endpoints =====

// GET /api/machines/:agent_id/sessions - Get all sessions for a machine
func (h *Handler) GetMachineSessions(c *gin.Context) {
	agentID := c.Param("agent_id")
	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)

	// Verify machine access
	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	// Check ownership
	if machine.OwnerID != userID {
		// Check if user has access
		username := c.GetString("username")
		hasAccess := false
		for _, allowedUser := range machine.AllowedUsers {
			if allowedUser == username {
				hasAccess = true
				break
			}
		}
		if !hasAccess {
			c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
			return
		}
	}

	sessPage, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	sessLimit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	if sessPage < 1 {
		sessPage = 1
	}
	if sessLimit < 1 || sessLimit > 200 {
		sessLimit = 25
	}
	sessSkip := (sessPage - 1) * sessLimit

	sessTotal, err := h.store.CountSessionsByMachine(machine.ID)
	if err != nil {
		sessTotal = 0
	}

	sessions, err := h.store.GetSessionsByMachinePaged(machine.ID, sessLimit, sessSkip)
	if err != nil {
		h.logger.Error("Failed to get sessions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get sessions"})
		return
	}

	sessTotalPages := int(sessTotal) / sessLimit
	if int(sessTotal)%sessLimit != 0 {
		sessTotalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions":    sessions,
		"total":       sessTotal,
		"page":        sessPage,
		"limit":       sessLimit,
		"total_pages": sessTotalPages,
	})
}

// GET /api/machines/:agent_id/sessions/active - Get active sessions for a machine
func (h *Handler) GetActiveSessions(c *gin.Context) {
	agentID := c.Param("agent_id")
	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)

	// Verify machine access
	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	// Check ownership
	if machine.OwnerID != userID {
		username := c.GetString("username")
		hasAccess := false
		for _, allowedUser := range machine.AllowedUsers {
			if allowedUser == username {
				hasAccess = true
				break
			}
		}
		if !hasAccess {
			c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
			return
		}
	}

	sessions, err := h.store.GetActiveSessionsByMachine(machine.ID)
	if err != nil {
		h.logger.Error("Failed to get active sessions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get active sessions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

// GET /api/sessions/:session_id - Get session details with logs
func (h *Handler) GetSessionDetails(c *gin.Context) {
	sessionID := c.Param("session_id")
	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)

	// Get session
	session, err := h.store.GetSessionByID(sessionID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}

	// Check authorization (user must own the session or have access to machine)
	if session.UserID != userID {
		machine, err := h.store.GetMachineByID(session.MachineID)
		if err != nil || machine.OwnerID != userID {
			username := c.GetString("username")
			hasAccess := false
			if machine != nil {
				for _, allowedUser := range machine.AllowedUsers {
					if allowedUser == username {
						hasAccess = true
						break
					}
				}
			}
			if !hasAccess {
				c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
				return
			}
		}
	}

	// Paginate session logs
	logPage, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	logLimit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	if logPage < 1 {
		logPage = 1
	}
	if logLimit < 1 || logLimit > 200 {
		logLimit = 25
	}
	logSkip := (logPage - 1) * logLimit

	logTotal, err := h.store.CountLogsBySession(sessionID)
	if err != nil {
		logTotal = 0
	}

	logs, err := h.store.GetLogsBySessionPaged(sessionID, logLimit, logSkip)
	if err != nil {
		logs = []*store.LogEntry{}
	}

	logTotalPages := int(logTotal) / logLimit
	if int(logTotal)%logLimit != 0 {
		logTotalPages++
	}

	// Get machine info
	machine, _ := h.store.GetMachineByID(session.MachineID)
	machineName := ""
	if machine != nil {
		machineName = machine.Name
	}

	c.JSON(http.StatusOK, gin.H{
		"session":          session,
		"logs":             logs,
		"machine_name":     machineName,
		"logs_total":       logTotal,
		"logs_page":        logPage,
		"logs_limit":       logLimit,
		"logs_total_pages": logTotalPages,
	})
}

// GET /api/machines/:agent_id/logs/search - Search logs
func (h *Handler) SearchMachineLogs(c *gin.Context) {
	agentID := c.Param("agent_id")
	query := c.Query("q")
	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)

	// Verify machine access
	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	// Check ownership
	if machine.OwnerID != userID {
		username := c.GetString("username")
		hasAccess := false
		for _, allowedUser := range machine.AllowedUsers {
			if allowedUser == username {
				hasAccess = true
				break
			}
		}
		if !hasAccess {
			c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
			return
		}
	}

	srchPage, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	srchLimit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	if srchPage < 1 {
		srchPage = 1
	}
	if srchLimit < 1 || srchLimit > 200 {
		srchLimit = 25
	}
	srchSkip := (srchPage - 1) * srchLimit

	logs, total, err := h.store.SearchLogsByMachinePaged(machine.ID, query, srchLimit, srchSkip)
	if err != nil {
		h.logger.Error("Failed to search logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search logs"})
		return
	}

	type EnrichedLog struct {
		*store.LogEntry
		Username string `json:"username"`
	}

	enrichedLogs := make([]EnrichedLog, 0, len(logs))
	for _, log := range logs {
		enrichedLogs = append(enrichedLogs, EnrichedLog{
			LogEntry: log,
			Username: log.Username,
		})
	}

	srchTotalPages := int(total) / srchLimit
	if int(total)%srchLimit != 0 {
		srchTotalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":        enrichedLogs,
		"total":       total,
		"page":        srchPage,
		"limit":       srchLimit,
		"total_pages": srchTotalPages,
	})
}

// containsIgnoreCase checks if str contains substr (case insensitive)
func containsIgnoreCase(str, substr string) bool {
	return len(str) >= len(substr) && (str == substr ||
		len(substr) == 0 ||
		findIgnoreCase(str, substr))
}

func findIgnoreCase(str, substr string) bool {
	for i := 0; i <= len(str)-len(substr); i++ {
		if equalFoldAt(str, substr, i) {
			return true
		}
	}
	return false
}

func equalFoldAt(str, substr string, pos int) bool {
	for j := 0; j < len(substr); j++ {
		c1 := str[pos+j]
		c2 := substr[j]
		if c1 != c2 {
			// Convert to lowercase and compare
			if c1 >= 'A' && c1 <= 'Z' {
				c1 += 'a' - 'A'
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 += 'a' - 'A'
			}
			if c1 != c2 {
				return false
			}
		}
	}
	return true
}
