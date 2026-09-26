package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-agent-backend/internal/logmanager"
	"github.com/vsay/vsay-agent-backend/internal/store"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ── Request/Response types ────────────────────────────────────────────────────

type logMgmtConfigRequest struct {
	RetentionDays    int    `json:"retention_days"`
	ArchiveEnabled   bool   `json:"archive_enabled"`
	ArchiveEveryDays int    `json:"archive_every_days"`
	StorageType      string `json:"storage_type"`
	StorageCreds     any    `json:"storage_creds,omitempty"` // raw creds (never returned)
}

// ── Middleware ────────────────────────────────────────────────────────────────

// SuperAdminOnly aborts with 403 if the caller is not super_admin.
func (h *Handler) SuperAdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString("role") != "super_admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "super_admin only"})
			return
		}
		c.Next()
	}
}

// AdminOrSuperAdmin aborts unless the caller is company_admin or super_admin.
func (h *Handler) AdminOrSuperAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetString("role")
		if role != "super_admin" && role != "company_admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin access required"})
			return
		}
		c.Next()
	}
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// GetLogManagementConfig returns the current log management config.
// Visible to company_admin + super_admin (creds are redacted).
func (h *Handler) GetLogManagementConfig(c *gin.Context) {
	cfg, err := h.store.GetLogManagementConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"retention_days":     cfg.RetentionDays,
		"archive_enabled":    cfg.ArchiveEnabled,
		"archive_every_days": cfg.ArchiveEveryDays,
		"storage_type":       cfg.StorageType,
		"storage_configured": len(cfg.StorageCredsEnc) > 0,
		"last_archive_at":    cfg.LastArchiveAt,
		"next_archive_at":    cfg.NextArchiveAt,
	})
}

// SaveLogManagementConfig saves the log management config.
// super_admin only.
func (h *Handler) SaveLogManagementConfig(c *gin.Context) {
	var req logMgmtConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.RetentionDays <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "retention_days must be > 0"})
		return
	}

	cfg, err := h.store.GetLogManagementConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	cfg.RetentionDays = req.RetentionDays
	cfg.ArchiveEnabled = req.ArchiveEnabled
	cfg.ArchiveEveryDays = req.ArchiveEveryDays
	cfg.StorageType = req.StorageType

	if req.StorageCreds != nil && req.StorageType != "" {
		encCreds, err := encryptStorageCreds(req.StorageType, req.StorageCreds)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid storage creds: " + err.Error()})
			return
		}
		cfg.StorageCredsEnc = encCreds
	}

	if err := h.store.UpsertLogManagementConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "saved"})
}

// TestStorageConnection tests connectivity to the given storage backend.
func (h *Handler) TestStorageConnection(c *gin.Context) {
	var req struct {
		StorageType  string `json:"storage_type"`
		StorageCreds any    `json:"storage_creds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.StorageType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "storage_type required"})
		return
	}

	encCreds, err := encryptStorageCreds(req.StorageType, req.StorageCreds)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	mgr := logmanager.NewManager(h.store, h.logger)
	if err := mgr.TestConnection(c.Request.Context(), req.StorageType, encCreds); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"status": "failed", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// TriggerArchiveNow runs archival immediately in the background.
func (h *Handler) TriggerArchiveNow(c *gin.Context) {
	mgr := logmanager.NewManager(h.store, h.logger)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		if err := mgr.RunArchival(ctx, "manual"); err != nil {
			h.logger.Sugar().Warnf("manual archive failed: %v", err)
		}
	}()
	c.JSON(http.StatusAccepted, gin.H{"status": "started"})
}

// GetArchiveRuns returns the last 10 archive run records.
func (h *Handler) GetArchiveRuns(c *gin.Context) {
	runs, err := h.store.GetArchiveRuns(10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if runs == nil {
		runs = []*store.ArchiveRun{}
	}
	c.JSON(http.StatusOK, runs)
}

// RestoreFromRun restores archived logs from a specific run back into MongoDB.
func (h *Handler) RestoreFromRun(c *gin.Context) {
	runID, err := primitive.ObjectIDFromHex(c.Param("run_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid run_id"})
		return
	}

	mgr := logmanager.NewManager(h.store, h.logger)
	logs, sessions, err := mgr.RestoreFromRun(c.Request.Context(), runID)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"logs_restored":     logs,
		"sessions_restored": sessions,
	})
}

// ── Helper ────────────────────────────────────────────────────────────────────

// encryptStorageCreds marshals the raw creds map into the typed struct, then encrypts.
func encryptStorageCreds(storageType string, rawCreds any) ([]byte, error) {
	raw, err := json.Marshal(rawCreds)
	if err != nil {
		return nil, err
	}

	switch storageType {
	case "s3":
		var c logmanager.S3Creds
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		return logmanager.EncryptCreds(c)
	case "gcs":
		var c logmanager.GCSCreds
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		return logmanager.EncryptCreds(c)
	case "azure":
		var c logmanager.AzureCreds
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		return logmanager.EncryptCreds(c)
	case "sftp":
		var c logmanager.SFTPCreds
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		return logmanager.EncryptCreds(c)
	case "nfs":
		var c logmanager.NFSCreds
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		return logmanager.EncryptCreds(c)
	case "elasticsearch":
		var c logmanager.ElasticsearchCreds
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		return logmanager.EncryptCreds(c)
	case "siem":
		var c logmanager.SIEMCreds
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		return logmanager.EncryptCreds(c)
	default:
		return nil, nil
	}
}
