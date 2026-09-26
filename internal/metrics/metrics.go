package metrics

import (
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	HTTPRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsay_backend_http_requests_total",
		Help: "Total number of HTTP requests",
	}, []string{"method", "path", "status_code"})

	HTTPRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vsay_backend_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})

	HTTPRequestsInFlight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vsay_backend_http_requests_in_flight",
		Help: "Current number of HTTP requests being processed",
	})

	GRPCActiveConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vsay_backend_grpc_active_connections",
		Help: "Number of currently active gRPC agent streams",
	})

	GRPCConnectionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsay_backend_grpc_connections_total",
		Help: "Total gRPC agent connections established",
	})

	GRPCDisconnectionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsay_backend_grpc_disconnections_total",
		Help: "Total gRPC agent disconnections",
	})

	AgentHeartbeatsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsay_backend_agent_heartbeats_total",
		Help: "Total heartbeat messages received from agents",
	})

	AgentCommandsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsay_backend_agent_commands_total",
		Help: "Total commands executed on agents",
	}, []string{"status"})

	TerminalSessionsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vsay_backend_terminal_sessions_active",
		Help: "Number of active terminal WebSocket sessions",
	})

	CertSignsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsay_backend_cert_signs_total",
		Help: "Total agent certificate signing requests",
	}, []string{"result"})

	BuildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vsay_backend_build_info",
		Help: "Build information",
	}, []string{"service", "goversion"})
)

func init() {
	BuildInfo.WithLabelValues("vsay-agent-backend", runtime.Version()).Set(1)
}
