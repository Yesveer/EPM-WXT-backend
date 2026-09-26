package api

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	emailsvc "github.com/vsay/vsay-agent-backend/internal/email"
	"github.com/vsay/vsay-agent-backend/internal/store"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// validAccessRequestStatuses are the five lifecycle states the admin-facing
// Access Requests page filters by (one tab per status).
var validAccessRequestStatuses = map[string]bool{
	"pending":  true,
	"approved": true, // "Active" tab — approved and not yet expired/revoked
	"expired":  true, // "Approved & Completed" tab — ran its full granted duration
	"rejected": true,
	"revoked":  true, // manually revoked by an admin while still active
}

// emailService is a package-level stateless email service instance.
var emailService = emailsvc.New()

// POST /api/access-requests
func (h *Handler) CreateAccessRequest(c *gin.Context) {
	var req struct {
		MachineID     string `json:"machine_id" binding:"required"`
		DurationHours int    `json:"duration_hours"` // 0 = no expiration
		RequestNote   string `json:"request_note"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 0 = no expiration; any positive value must be at most 8760h (1 year)
	if req.DurationHours < 0 || req.DurationHours > 8760 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "duration_hours must be 0 (no expiration) or between 1 and 8760"})
		return
	}

	machineID, err := primitive.ObjectIDFromHex(req.MachineID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid machine_id"})
		return
	}

	machine, err := h.store.GetMachineByID(machineID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}

	requesterID := c.GetString("user_id")
	requesterUsername := c.GetString("username")
	requesterEmail := c.GetString("email")
	tenantID := c.GetString("tenant_id")

	// Check same tenant
	if machine.TenantID != tenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "machine belongs to a different tenant"})
		return
	}

	// Check not already owner
	userID, _ := primitive.ObjectIDFromHex(requesterID)
	if machine.OwnerID == userID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "you are the owner of this machine"})
		return
	}

	// Check not already pending for this machine+requester
	existingRequests, err := h.store.GetAccessRequestsByMachine(machineID)
	if err == nil {
		for _, ar := range existingRequests {
			if ar.RequesterID == requesterID && ar.Status == "pending" {
				c.JSON(http.StatusConflict, gin.H{"error": "you already have a pending access request for this machine"})
				return
			}
		}
	}

	accessReq := &store.AccessRequest{
		MachineID:         machineID,
		MachineName:       machine.Name,
		MachineAgentID:    machine.AgentID,
		RequesterID:       requesterID,
		RequesterUsername: requesterUsername,
		RequesterEmail:    requesterEmail,
		TenantID:          tenantID,
		OwnerID:           machine.OwnerID.Hex(),
		OwnerEmail:        "", // not available at creation time
		RequestNote:       req.RequestNote,
		DurationHours:     req.DurationHours,
		Status:            "pending",
	}

	if err := h.store.CreateAccessRequest(accessReq); err != nil {
		h.logger.Error("Failed to create access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create access request"})
		return
	}

	// Attempt to notify owner via email if owner_email is known (best-effort)
	if accessReq.OwnerEmail != "" {
		go func() {
			if err := emailService.SendAccessRequestNotification(
				accessReq.OwnerEmail, "",
				requesterUsername, machine.Name,
				req.DurationHours, req.RequestNote,
			); err != nil {
				h.logger.Warn("Failed to send access request notification email", zap.Error(err))
			}
		}()
	}

	c.JSON(http.StatusCreated, accessReq)
}

// GET /api/access-requests/my
func (h *Handler) GetMyAccessRequests(c *gin.Context) {
	requesterID := c.GetString("user_id")
	tenantID := c.GetString("tenant_id")

	requests, err := h.store.GetAccessRequestsByRequester(requesterID, tenantID)
	if err != nil {
		h.logger.Error("Failed to get access requests", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get access requests"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"requests": requests, "total": len(requests)})
}

// GET /api/machines/:agent_id/access-requests
func (h *Handler) GetMachineAccessRequests(c *gin.Context) {
	agentID := c.Param("agent_id")
	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)
	role := c.GetString("role")

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}

	// Only owner or admin can view access requests
	if machine.OwnerID != userID && role != "company_admin" && role != "super_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "not authorized"})
		return
	}

	requests, err := h.store.GetAccessRequestsByMachine(machine.ID)
	if err != nil {
		h.logger.Error("Failed to get machine access requests", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get access requests"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"requests": requests, "total": len(requests)})
}

// GET /api/machines/:agent_id/pending-requests-count
func (h *Handler) GetPendingRequestsCount(c *gin.Context) {
	agentID := c.Param("agent_id")
	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)
	role := c.GetString("role")

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}

	// Only owner or admin can view count
	if machine.OwnerID != userID && role != "company_admin" && role != "super_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "not authorized"})
		return
	}

	requests, err := h.store.GetAccessRequestsByMachine(machine.ID)
	if err != nil {
		h.logger.Error("Failed to get machine access requests", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get access requests"})
		return
	}

	count := 0
	for _, r := range requests {
		if r.Status == "pending" {
			count++
		}
	}

	c.JSON(http.StatusOK, gin.H{"count": count})
}

// POST /api/access-requests/:id/approve
func (h *Handler) ApproveAccessRequest(c *gin.Context) {
	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request id"})
		return
	}

	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)
	approverUsername := c.GetString("username")
	role := c.GetString("role")

	ar, err := h.store.GetAccessRequestByID(id)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "access request not found"})
			return
		}
		h.logger.Error("Failed to get access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get access request"})
		return
	}

	if ar.Status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "access request is not pending"})
		return
	}

	// Verify caller is owner of the machine or admin
	machine, err := h.store.GetMachineByID(ar.MachineID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}

	if machine.OwnerID != userID && role != "company_admin" && role != "super_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "not authorized"})
		return
	}

	now := time.Now()

	ar.Status = "approved"
	ar.ApprovedBy = approverUsername
	ar.ApprovedAt = &now

	// Only set an expiry when the requester asked for a time-limited grant
	var expiresAt *time.Time
	if ar.DurationHours > 0 {
		t := now.Add(time.Duration(ar.DurationHours) * time.Hour)
		expiresAt = &t
		ar.ExpiresAt = expiresAt
	}

	if err := h.store.UpdateAccessRequest(ar); err != nil {
		h.logger.Error("Failed to update access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to approve request"})
		return
	}

	// Grant machine access
	if err := h.store.GrantMachineAccess(ar.MachineID, ar.RequesterUsername); err != nil {
		h.logger.Error("Failed to grant machine access", zap.Error(err))
		// Non-fatal — request is marked approved, access grant can be retried
	}

	// Send approval email (best-effort, async)
	if ar.RequesterEmail != "" {
		go func() {
			if err := emailService.SendAccessRequestDecision(
				ar.RequesterEmail, ar.RequesterUsername,
				ar.MachineName, "approved", "", expiresAt,
			); err != nil {
				h.logger.Warn("Failed to send approval email", zap.Error(err))
			}
		}()
	}

	c.JSON(http.StatusOK, gin.H{"message": "access request approved", "request": ar})
}

// POST /api/access-requests/:id/reject
func (h *Handler) RejectAccessRequest(c *gin.Context) {
	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request id"})
		return
	}

	var body struct {
		Comment string `json:"comment"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if body.Comment == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "comment is required when rejecting an access request"})
		return
	}

	userIDStr := c.GetString("user_id")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)
	rejectorUsername := c.GetString("username")
	role := c.GetString("role")

	ar, err := h.store.GetAccessRequestByID(id)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "access request not found"})
			return
		}
		h.logger.Error("Failed to get access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get access request"})
		return
	}

	if ar.Status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "access request is not pending"})
		return
	}

	// Verify caller is owner of the machine or admin
	machine, err := h.store.GetMachineByID(ar.MachineID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}

	if machine.OwnerID != userID && role != "company_admin" && role != "super_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "not authorized"})
		return
	}

	ar.Status = "rejected"
	ar.RejectedBy = rejectorUsername
	ar.RejectComment = body.Comment

	if err := h.store.UpdateAccessRequest(ar); err != nil {
		h.logger.Error("Failed to update access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reject request"})
		return
	}

	// Send rejection email (best-effort, async)
	if ar.RequesterEmail != "" {
		go func() {
			if err := emailService.SendAccessRequestDecision(
				ar.RequesterEmail, ar.RequesterUsername,
				ar.MachineName, "rejected", body.Comment, nil,
			); err != nil {
				h.logger.Warn("Failed to send rejection email", zap.Error(err))
			}
		}()
	}

	c.JSON(http.StatusOK, gin.H{"message": "access request rejected", "request": ar})
}

// GET /api/access-requests — admin/super_admin only (route-gated).
// Powers the sidebar "Access Requests" page: one status tab at a time, with
// server-side search + pagination. company_admin is scoped to their own
// tenant; super_admin sees all tenants, or one via ?tenant_id=.
func (h *Handler) ListAccessRequests(c *gin.Context) {
	role := c.GetString("role")
	tenantID := c.GetString("tenant_id")

	status := c.Query("status")
	if !validAccessRequestStatuses[status] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be one of pending, approved, expired, rejected, revoked"})
		return
	}

	search := strings.TrimSpace(c.Query("search"))

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	if limit < 1 || limit > 200 {
		limit = 25
	}

	filterTenantID := tenantID
	if role == "super_admin" {
		filterTenantID = c.Query("tenant_id")
	}

	skip := (page - 1) * limit
	reqs, total, err := h.store.GetAccessRequestsFiltered(filterTenantID, status, search, limit, skip)
	if err != nil {
		h.logger.Error("Failed to list access requests", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list access requests"})
		return
	}

	totalPages := int(math.Ceil(float64(total) / float64(limit)))
	if totalPages < 1 {
		totalPages = 1
	}

	c.JSON(http.StatusOK, gin.H{
		"requests":    reqs,
		"total":       total,
		"page":        page,
		"limit":       limit,
		"total_pages": totalPages,
	})
}

// POST /api/access-requests/:id/revoke — admin/super_admin only (route-gated).
// Cuts short an active (approved) grant mid-session — distinct from natural
// expiry, which the background ticker marks "expired" instead.
func (h *Handler) RevokeAccessRequest(c *gin.Context) {
	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request id"})
		return
	}

	revokerUsername := c.GetString("username")

	ar, err := h.store.GetAccessRequestByID(id)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "access request not found"})
			return
		}
		h.logger.Error("Failed to get access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get access request"})
		return
	}

	if ar.Status != "approved" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only an active access request can be revoked"})
		return
	}

	now := time.Now()
	ar.Status = "revoked"
	ar.RevokedBy = revokerUsername
	ar.RevokedAt = &now

	if err := h.store.RevokeMachineAccess(ar.MachineID, ar.RequesterUsername); err != nil {
		h.logger.Error("Failed to revoke machine access", zap.Error(err))
		// Non-fatal — the request is still marked revoked below
	}

	if err := h.store.UpdateAccessRequest(ar); err != nil {
		h.logger.Error("Failed to update access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke request"})
		return
	}

	if ar.RequesterEmail != "" {
		go func() {
			if err := emailService.SendAccessRequestDecision(
				ar.RequesterEmail, ar.RequesterUsername,
				ar.MachineName, "revoked", "", nil,
			); err != nil {
				h.logger.Warn("Failed to send revoke email", zap.Error(err))
			}
		}()
	}

	c.JSON(http.StatusOK, gin.H{"message": "access request revoked", "request": ar})
}
