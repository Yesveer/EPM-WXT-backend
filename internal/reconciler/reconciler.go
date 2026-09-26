package reconciler

import (
	"context"
	"time"

	"github.com/vsay/vsay-agent-backend/internal/store"
	"go.uber.org/zap"
)

type Reconciler struct {
	store          store.Store
	logger         *zap.Logger
	interval       time.Duration
	offlineTimeout time.Duration
}

func New(s store.Store, l *zap.Logger, interval, offlineTimeout time.Duration) *Reconciler {
	return &Reconciler{
		store:          s,
		logger:         l,
		interval:       interval,
		offlineTimeout: offlineTimeout,
	}
}

func (r *Reconciler) Start(ctx context.Context) {
	r.logger.Info("Reconciler started",
		zap.Duration("interval", r.interval),
		zap.Duration("offline_timeout", r.offlineTimeout))

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	// Run immediately on start
	r.checkOfflineMachines(ctx)

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("Reconciler stopped")
			return
		case <-ticker.C:
			r.checkOfflineMachines(ctx)
		}
	}
}

func (r *Reconciler) checkOfflineMachines(ctx context.Context) {
	if err := r.store.MarkInactiveMachinesOffline(r.offlineTimeout); err != nil {
		r.logger.Error("Failed to mark inactive machines offline", zap.Error(err))
		return
	}

	// Count by status using index-only scans — does NOT load full documents.
	// This replaces the previous GetAllMachines() O(N) full scan.
	online, offline, pending, err := r.store.CountMachinesByStatus()
	if err != nil {
		r.logger.Error("Failed to count machines by status", zap.Error(err))
		return
	}

	r.logger.Debug("Reconciler check completed",
		zap.Int64("total", online+offline+pending),
		zap.Int64("online", online),
		zap.Int64("offline", offline),
		zap.Int64("pending", pending))
}
