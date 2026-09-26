package logmanager

import (
	"context"
	"time"

	"github.com/vsay/vsay-agent-backend/internal/store"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

// Reconciler runs on a schedule and triggers archival/deletion when due.
type Reconciler struct {
	manager  *Manager
	store    store.Store
	logger   *zap.Logger
	interval time.Duration
}

func NewReconciler(m *Manager, s store.Store, logger *zap.Logger) *Reconciler {
	return &Reconciler{
		manager:  m,
		store:    s,
		logger:   logger,
		interval: 1 * time.Hour,
	}
}

// Run starts the reconcile loop and blocks until ctx is cancelled.
func (r *Reconciler) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	r.reconcile(ctx)

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("Log management reconciler stopped")
			return
		case <-ticker.C:
			r.reconcile(ctx)
		}
	}
}

func (r *Reconciler) reconcile(ctx context.Context) {
	cfg, err := r.store.GetLogManagementConfig()
	if err != nil {
		r.logger.Warn("reconciler: load config failed", zap.Error(err))
		return
	}
	if cfg.RetentionDays <= 0 {
		return
	}

	if cfg.ArchiveEnabled && cfg.ArchiveEveryDays > 0 {
		due := cfg.NextArchiveAt == nil || time.Now().After(*cfg.NextArchiveAt)
		if due {
			r.logger.Info("Scheduled log archival triggered")
			if err := r.manager.RunArchival(ctx, "auto"); err != nil {
				r.logger.Error("Scheduled log archival failed", zap.Error(err))
			}
		}
		return
	}

	// Archiving disabled — only delete expired logs from DB
	cutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)
	r.deleteExpiredLogs(ctx, cutoff)
}

func (r *Reconciler) deleteExpiredLogs(ctx context.Context, cutoff time.Time) {
	_ = ctx
	var totalDeleted int64

	for {
		logs, err := r.store.GetLogsOlderThan(cutoff, 500)
		if err != nil {
			r.logger.Warn("deleteExpiredLogs: query failed", zap.Error(err))
			break
		}
		if len(logs) == 0 {
			break
		}

		ids := make([]primitive.ObjectID, len(logs))
		for i, l := range logs {
			ids[i] = l.ID
		}
		deleted, err := r.store.DeleteLogsByIDs(ids)
		if err != nil {
			r.logger.Warn("deleteExpiredLogs: delete failed", zap.Error(err))
			break
		}
		totalDeleted += deleted

		sessions, _ := r.store.GetSessionsOlderThan(cutoff, 500)
		if len(sessions) > 0 {
			sessIDs := make([]primitive.ObjectID, len(sessions))
			for i, s := range sessions {
				sessIDs[i] = s.ID
			}
			if _, derr := r.store.DeleteSessionsByIDs(sessIDs); derr != nil {
				r.logger.Warn("deleteExpiredLogs: session cleanup failed", zap.Error(derr))
			}
		}

		auditLogs, _ := r.store.GetAuditLogsOlderThan(cutoff, 500)
		if len(auditLogs) > 0 {
			auditIDs := make([]primitive.ObjectID, len(auditLogs))
			for i, a := range auditLogs {
				auditIDs[i] = a.ID
			}
			if _, derr := r.store.DeleteAuditLogsByIDs(auditIDs); derr != nil {
				r.logger.Warn("deleteExpiredLogs: audit log cleanup failed", zap.Error(derr))
			}
		}

		if len(logs) < 500 {
			break
		}
	}

	if totalDeleted > 0 {
		r.logger.Info("Expired logs deleted", zap.Int64("count", totalDeleted))
	}
}
