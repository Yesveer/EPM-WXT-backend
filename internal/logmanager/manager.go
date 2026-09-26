package logmanager

import (
	"context"
	"fmt"
	"time"

	"github.com/vsay/vsay-agent-backend/internal/store"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

const batchSize = 1000

// Manager orchestrates log archival and deletion.
type Manager struct {
	store  store.Store
	logger *zap.Logger
}

func NewManager(s store.Store, logger *zap.Logger) *Manager {
	return &Manager{store: s, logger: logger}
}

// RunArchival archives logs older than the configured retention period and removes them from DB.
// trigger is "auto" or "manual".
func (m *Manager) RunArchival(ctx context.Context, trigger string) error {
	cfg, err := m.store.GetLogManagementConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.RetentionDays <= 0 {
		return fmt.Errorf("retention_days not set — nothing to archive")
	}

	cutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)

	run := &store.ArchiveRun{
		StartedAt:   time.Now(),
		Status:      "running",
		StorageType: cfg.StorageType,
		Trigger:     trigger,
	}
	if err := m.store.CreateArchiveRun(run); err != nil {
		return fmt.Errorf("create archive run: %w", err)
	}

	m.logger.Info("Log archival started",
		zap.String("trigger", trigger),
		zap.Time("cutoff", cutoff),
		zap.String("storage", cfg.StorageType),
		zap.String("run_id", run.ID.Hex()))

	var (
		logsArchived     int64
		sessionsArchived int64
		logsDeleted      int64
		bytesArchived    int64
		archiveKey       string
		runErr           string
	)

	// ── Determine archiver ────────────────────────────────────────────────────
	var arch Archiver
	if cfg.ArchiveEnabled && cfg.StorageType != "" && len(cfg.StorageCredsEnc) > 0 {
		arch, err = NewArchiver(cfg.StorageType, cfg.StorageCredsEnc)
		if err != nil {
			runErr = err.Error()
			m.finishRun(run.ID, "failed", runErr, 0, 0, 0, 0)
			return fmt.Errorf("build archiver: %w", err)
		}
	}

	// ── Batch logs ────────────────────────────────────────────────────────────
	prefix := ""
	if arch != nil {
		archiveKey = BuildArchiveKey(prefix, time.Now())
	}

	for {
		logs, err := m.store.GetLogsOlderThan(cutoff, batchSize)
		if err != nil {
			runErr = err.Error()
			break
		}
		if len(logs) == 0 {
			break
		}

		sessions, _ := m.store.GetSessionsOlderThan(cutoff, batchSize)
		auditLogs, _ := m.store.GetAuditLogsOlderThan(cutoff, batchSize)

		if arch != nil {
			data, err := MarshalArchive(logs, sessions, auditLogs)
			if err != nil {
				m.logger.Warn("marshal archive batch failed", zap.Error(err))
			} else {
				key := archiveKey
				if logsArchived > 0 {
					key = BuildArchiveKey(prefix, time.Now())
				}
				if err := arch.Upload(ctx, key, data); err != nil {
					m.logger.Warn("upload batch failed", zap.Error(err))
					runErr = err.Error()
					break
				}
				bytesArchived += int64(len(data))
				logsArchived += int64(len(logs))
				sessionsArchived += int64(len(sessions))
			}
		}

		// Delete from DB regardless of whether archival succeeded
		logIDs := make([]primitive.ObjectID, len(logs))
		for i, l := range logs {
			logIDs[i] = l.ID
		}
		deleted, err := m.store.DeleteLogsByIDs(logIDs)
		if err != nil {
			m.logger.Warn("delete logs batch failed", zap.Error(err))
		}
		logsDeleted += deleted

		if len(sessions) > 0 {
			sessIDs := make([]primitive.ObjectID, len(sessions))
			for i, s := range sessions {
				sessIDs[i] = s.ID
			}
			if _, derr := m.store.DeleteSessionsByIDs(sessIDs); derr != nil {
				m.logger.Warn("archive: session cleanup failed", zap.Error(derr))
			}
		}

		if len(auditLogs) > 0 {
			auditIDs := make([]primitive.ObjectID, len(auditLogs))
			for i, a := range auditLogs {
				auditIDs[i] = a.ID
			}
			if _, derr := m.store.DeleteAuditLogsByIDs(auditIDs); derr != nil {
				m.logger.Warn("archive: audit log cleanup failed", zap.Error(derr))
			}
		}

		if len(logs) < batchSize {
			break // last batch
		}
	}

	// ── Update config: last/next archive timestamps ──────────────────────────
	now := time.Now()
	cfg.LastArchiveAt = &now
	if cfg.ArchiveEveryDays > 0 {
		next := now.AddDate(0, 0, cfg.ArchiveEveryDays)
		cfg.NextArchiveAt = &next
	}
	if err := m.store.UpsertLogManagementConfig(cfg); err != nil {
		m.logger.Warn("archive: failed to persist last/next archive timestamps", zap.Error(err))
	}

	status := "success"
	if runErr != "" {
		if logsDeleted > 0 {
			status = "partial"
		} else {
			status = "failed"
		}
	}

	m.finishRun(run.ID, status, runErr, logsArchived, sessionsArchived, logsDeleted, bytesArchived)
	m.logger.Info("Log archival finished",
		zap.String("status", status),
		zap.Int64("logs_archived", logsArchived),
		zap.Int64("logs_deleted", logsDeleted),
		zap.Int64("bytes_archived", bytesArchived))

	if runErr != "" {
		return fmt.Errorf("archival completed with error: %s", runErr)
	}
	return nil
}

// TestConnection verifies that the external storage configuration is reachable.
func (m *Manager) TestConnection(ctx context.Context, storageType string, encCreds []byte) error {
	arch, err := NewArchiver(storageType, encCreds)
	if err != nil {
		return err
	}
	return arch.TestConnection(ctx)
}

// RestoreFromRun re-inserts archived records from a previous ArchiveRun back into MongoDB.
func (m *Manager) RestoreFromRun(ctx context.Context, runID primitive.ObjectID) (int, int, error) {
	run, err := m.store.GetArchiveRunByID(runID)
	if err != nil {
		return 0, 0, fmt.Errorf("run not found: %w", err)
	}
	if run.ArchiveKey == "" {
		return 0, 0, fmt.Errorf("run has no archive key — nothing to restore")
	}

	cfg, err := m.store.GetLogManagementConfig()
	if err != nil {
		return 0, 0, fmt.Errorf("load config: %w", err)
	}
	if !cfg.ArchiveEnabled || cfg.StorageType == "" {
		return 0, 0, fmt.Errorf("archive storage not configured")
	}

	arch, err := NewArchiver(cfg.StorageType, cfg.StorageCredsEnc)
	if err != nil {
		return 0, 0, fmt.Errorf("build archiver: %w", err)
	}

	data, err := arch.Download(ctx, run.ArchiveKey)
	if err != nil {
		return 0, 0, fmt.Errorf("download archive: %w", err)
	}

	logs, sessions, auditLogs, err := UnmarshalArchive(data)
	if err != nil {
		return 0, 0, fmt.Errorf("parse archive: %w", err)
	}

	var restoredLogs, restoredSessions int
	for _, l := range logs {
		l.ID = primitive.NilObjectID
		if err := m.store.CreateLog(l); err == nil {
			restoredLogs++
		}
	}
	for _, s := range sessions {
		s.ID = primitive.NilObjectID
		if err := m.store.CreateSession(s); err == nil {
			restoredSessions++
		}
	}
	restoredAuditLogs := 0
	for _, a := range auditLogs {
		a.ID = primitive.NilObjectID
		if err := m.store.CreateAuditLog(a); err == nil {
			restoredAuditLogs++
		}
	}

	m.logger.Info("Log restore completed",
		zap.String("run_id", runID.Hex()),
		zap.Int("logs", restoredLogs),
		zap.Int("sessions", restoredSessions),
		zap.Int("audit_logs", restoredAuditLogs))

	return restoredLogs, restoredSessions, nil
}

func (m *Manager) finishRun(id primitive.ObjectID, status, errMsg string, logsArchived, sessionsArchived, logsDeleted, bytesArchived int64) {
	if err := m.store.UpdateArchiveRunFinished(id, status, errMsg, logsArchived, sessionsArchived, logsDeleted, bytesArchived); err != nil {
		m.logger.Warn("failed to update archive run", zap.Error(err))
	}
}
