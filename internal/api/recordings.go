package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	s3client "github.com/vsay/vsay-agent-backend/internal/s3"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// GET /api/machines/:agent_id/recordings — list session recordings for a machine
func (h *Handler) GetMachineRecordings(c *gin.Context) {
	agentID := c.Param("agent_id")

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	skip, _ := strconv.Atoi(c.DefaultQuery("skip", "0"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	recordings, err := h.store.GetRecordingsByMachine(machine.ID, limit, skip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load recordings"})
		return
	}

	total, _ := h.store.CountRecordingsByMachine(machine.ID)

	c.JSON(http.StatusOK, gin.H{
		"recordings": recordings,
		"total":      total,
		"limit":      limit,
		"skip":       skip,
	})
}

// GET /api/recordings/:id/url — get a pre-signed download URL for a recording
func (h *Handler) GetRecordingURL(c *gin.Context) {
	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid recording id"})
		return
	}

	recording, err := h.store.GetRecordingByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "recording not found"})
		return
	}

	// Load tenant S3 config
	tenantCfg, err := h.store.GetTenantConfig(recording.TenantID)
	if err != nil || !tenantCfg.S3.Enabled {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "S3 not configured for this tenant"})
		return
	}

	s3cfg := tenantCfg.S3
	client, err := s3client.NewClient(s3cfg.Endpoint, s3cfg.Protocol, s3cfg.AccessKey, s3cfg.SecretKey, s3cfg.Region, s3cfg.Bucket)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create S3 client"})
		return
	}

	url, err := client.PresignedURL(c.Request.Context(), recording.S3Key, 15*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate download URL"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"url":        url,
		"expires_in": 900, // 15 minutes in seconds
		"recording":  recording,
	})
}
