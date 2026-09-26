package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-agent-backend/internal/store"
)

// GET /api/config/s3 — returns the S3 config for the caller's tenant
func (h *Handler) GetS3Config(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	cfg, err := h.store.GetTenantConfig(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load config"})
		return
	}

	// Never expose the secret key in the response
	resp := gin.H{
		"enabled":            cfg.S3.Enabled,
		"endpoint":           cfg.S3.Endpoint,
		"protocol":           cfg.S3.Protocol,
		"access_key":         cfg.S3.AccessKey,
		"secret_key_set":     cfg.S3.SecretKey != "",
		"bucket":             cfg.S3.Bucket,
		"region":             cfg.S3.Region,
	}
	c.JSON(http.StatusOK, resp)
}

// POST /api/config/s3 — upserts S3 config for the caller's tenant (admin only)
func (h *Handler) SaveS3Config(c *gin.Context) {
	role := c.GetString("role")
	if role != "super_admin" && role != "company_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin access required"})
		return
	}

	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	var body struct {
		Enabled   bool   `json:"enabled"`
		Endpoint  string `json:"endpoint"`
		Protocol  string `json:"protocol"`
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"` // empty means "keep existing"
		Bucket    string `json:"bucket"`
		Region    string `json:"region"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Load existing config so we can preserve the secret key if not provided
	existing, err := h.store.GetTenantConfig(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load existing config"})
		return
	}

	secretKey := body.SecretKey
	if secretKey == "" {
		secretKey = existing.S3.SecretKey // keep existing secret key
	}

	cfg := &store.TenantConfig{
		TenantID: tenantID,
		S3: store.S3Config{
			Enabled:   body.Enabled,
			Endpoint:  body.Endpoint,
			Protocol:  body.Protocol,
			AccessKey: body.AccessKey,
			SecretKey: secretKey,
			Bucket:    body.Bucket,
			Region:    body.Region,
		},
	}

	if err := h.store.UpsertTenantConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save config"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "S3 configuration saved"})
}
