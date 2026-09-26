package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vsay/vsay-agent-backend/internal/api"
	"github.com/vsay/vsay-agent-backend/internal/ca"
	"github.com/vsay/vsay-agent-backend/internal/grpc"
	logmgr "github.com/vsay/vsay-agent-backend/internal/logmanager"
	"github.com/vsay/vsay-agent-backend/internal/metrics"
	agentmiddleware "github.com/vsay/vsay-agent-backend/internal/middleware"
	"github.com/vsay/vsay-agent-backend/internal/reconciler"
	"github.com/vsay/vsay-agent-backend/internal/store"
	"github.com/vsay/vsay-agent-backend/internal/upload"
	agentv1 "github.com/vsay/vsay-agent-backend/proto/agent/v1"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// validRedirectHost matches a syntactically plausible hostname (letters, digits,
// dots, hyphens) — used to sanity-check the Host header before it's echoed back
// into an HTTP->HTTPS redirect Location.
var validRedirectHost = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

func main() {
	// Custom Logger setup to match: 2026-01-21 00:35:39 | INFO | message | {"fields": "value"}
	loggerConfig := zap.Config{
		Level:       zap.NewAtomicLevelAt(zap.InfoLevel),
		Development: true,
		Encoding:    "console",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:       "ts",
			LevelKey:      "level",
			NameKey:       "logger",
			CallerKey:     "", // Hidden as per request
			FunctionKey:   zapcore.OmitKey,
			MessageKey:    "msg",
			StacktraceKey: "stacktrace",
			LineEnding:    zapcore.DefaultLineEnding,
			EncodeLevel:   zapcore.CapitalLevelEncoder,
			EncodeTime: func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
				enc.AppendString(t.Format("2006-01-02 15:04:05"))
			},
			EncodeDuration:   zapcore.StringDurationEncoder,
			EncodeCaller:     zapcore.ShortCallerEncoder,
			ConsoleSeparator: " | ",
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}
	logger, _ := loggerConfig.Build()
	defer logger.Sync()

	// Load .env
	if err := godotenv.Load(); err != nil {
		logger.Warn("No .env file found")
	}

	// Config (Env vars)
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	mongoDBName := os.Getenv("MONGO_DB_NAME")
	if mongoDBName == "" {
		mongoDBName = "vsay-test"
	}

	// JWT authentication is now handled by vsay-auth - no local JWT secret needed

	// TLS Configuration
	tlsEnabled := os.Getenv("TLS_ENABLED") == "true"
	tlsCertFile := os.Getenv("TLS_CERT_FILE")
	if tlsCertFile == "" {
		tlsCertFile = "./certs/server-cert.pem"
	}
	tlsKeyFile := os.Getenv("TLS_KEY_FILE")
	if tlsKeyFile == "" {
		tlsKeyFile = "./certs/server-key.pem"
	}
	caCertFile := os.Getenv("CA_CERT_FILE")
	if caCertFile == "" {
		caCertFile = "./certs/ca-cert.pem"
	}
	caKeyFile := os.Getenv("CA_KEY_FILE")
	if caKeyFile == "" {
		caKeyFile = "./certs/ca-key.pem"
	}
	serverDomain := os.Getenv("SERVER_DOMAIN")
	if serverDomain == "" {
		serverDomain = "localhost"
	}
	httpsPort := os.Getenv("HTTPS_PORT")
	if httpsPort == "" {
		httpsPort = "8443"
	}
	// Reconciler Config
	reconcilerIntervalStr := os.Getenv("RECONCILER_INTERVAL")
	reconcilerInterval := 1 * time.Minute
	if val, err := time.ParseDuration(reconcilerIntervalStr); err == nil {
		reconcilerInterval = val
	}

	offlineTimeoutStr := os.Getenv("OFFLINE_TIMEOUT")
	offlineTimeout := 2 * time.Minute
	if val, err := time.ParseDuration(offlineTimeoutStr); err == nil {
		offlineTimeout = val
	}

	// Cloudinary Config (Placeholder for future implementation)
	cloudinaryURL := os.Getenv("CLOUDINARY_URL")
	if cloudinaryURL != "" {
		logger.Info("Cloudinary configuration found", zap.String("url", "configured"))
	} else {
		logger.Info("Cloudinary configuration not found")
	}

	// Private CA — load or auto-generate (signs agent client certs)
	caManager, err := ca.LoadOrCreate(caCertFile, caKeyFile, logger)
	if err != nil {
		logger.Fatal("Failed to initialize Private CA", zap.Error(err))
	}
	logger.Info("Private CA ready")

	// Auto-generate or refresh the server TLS cert from the CA (30-day validity)
	if err := caManager.EnsureServerCert(tlsCertFile, tlsKeyFile, serverDomain); err != nil {
		logger.Fatal("Failed to ensure server TLS cert", zap.Error(err))
	}
	logger.Info("Server TLS cert ready", zap.String("domain", serverDomain))

	// Store
	st, err := store.NewMongoDB(mongoURI, mongoDBName)
	if err != nil {
		logger.Fatal("Failed to connect to MongoDB", zap.Error(err))
	}
	logger.Info("Connected to MongoDB")

	// A freshly-started backend holds no agent connections — any "online" status in
	// the DB is stale (left by a previously-killed process). Reset everything to
	// offline; live agents reconnect within seconds and flip themselves back online.
	if err := st.MarkAllMachinesOffline(); err != nil {
		logger.Warn("Failed to reset machine statuses to offline on startup", zap.Error(err))
	} else {
		logger.Info("Reset all machine statuses to offline on startup")
	}

	// Services
	agentManager := grpc.NewAgentManager()
	rec := reconciler.New(st, logger, reconcilerInterval, offlineTimeout)
	uploadService, err := upload.NewService(logger)
	if err != nil {
		logger.Warn("Failed to initialize upload service", zap.Error(err))
	}

	// HTTP Handler (create early to wire terminal manager)
	// Auth is now handled by vsay-auth gateway, no local auth service needed
	h := api.NewHandler(st, agentManager, uploadService, logger)

	// RDP tunnel manager (remote-desktop feature) — bridges guacd ↔ agent tunnel.
	rdpManager := api.NewRDPManager(agentManager, st, logger)
	h.SetRDPManager(rdpManager)

	// Remote control (AnyDesk-style): the admin joins the user's LIVE desktop
	// session instead of opening a new one. It reuses the RDP manager's tunnel
	// and guacd plumbing; only the orchestration differs.
	rcManager := api.NewRemoteControlManager(agentManager, st, rdpManager, logger)
	h.SetRemoteControlManager(rcManager)

	// gRPC Server — intentionally public: this is the port agents dial in on.
	lis, err := net.Listen("tcp", ":8081") // #nosec G102 -- deliberately public agent-facing port
	if err != nil {
		logger.Fatal("Failed to listen for gRPC", zap.Error(err))
	}

	// gRPC Server — mTLS with dynamic per-connection cert + CA pool (hot-reload after rotation)
	grpcServer := googlegrpc.NewServer(googlegrpc.Creds(credentials.NewTLS(caManager.ServerTLSConfig(tlsCertFile, tlsKeyFile))))
	logger.Info("gRPC server configured with mTLS (dynamic per-connection, TLS 1.3)")

	agentServer := grpc.NewAgentServer(st, agentManager, logger)
	agentServer.SetTerminalManager(h.GetTerminalManager()) // Wire terminal manager
	agentServer.SetRDPHandler(rdpManager)                  // Route rdp_ session output to RDP tunnels
	agentServer.SetRemoteControlHandler(rcManager)         // Route rc_ session output to remote control
	agentv1.RegisterAgentServiceServer(grpcServer, agentServer)

	// HTTP Server
	gin.SetMode(gin.ReleaseMode) // Disable debug logs
	r := gin.New()               // Create without default middleware
	r.Use(gin.Recovery())        // Add recovery middleware only
	r.Use(agentmiddleware.MetricsMiddleware())
	// CORS is handled by vsay-auth gateway - no need for CORS here

	// Health check endpoint (liveness)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "vsay-agent-backend"})
	})

	// Readiness endpoint — checks MongoDB connectivity
	r.GET("/ready", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
		defer cancel()
		if err := st.Ping(ctx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "unavailable",
				"checks": gin.H{"mongodb": "error", "error": err.Error()},
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"checks": gin.H{"mongodb": "ok"},
		})
	})

	// Prometheus metrics endpoint
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// gRPC mode endpoint — agent calls this to know whether to use mTLS or TLS
	r.GET("/grpc-mode", func(c *gin.Context) {
		mtls := os.Getenv("GRPC_MTLS_ENABLED") == "true" || os.Getenv("GRPC_mTLS_ENABLED") == "true"
		c.JSON(http.StatusOK, gin.H{"mtls_enabled": mtls})
	})

	// Agent cert signing — called by agents during configure/renewal
	// Auth: Bearer <registration_token>
	// Header X-Cert-Fingerprint: <sha256-of-current-cert>  (optional on first sign, required on renewal)
	r.POST("/agent/sign-cert", func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")

		machine, err := st.GetMachineByRegistrationToken(token)
		if err != nil || machine == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		// Immediately reject revoked machines — no new certs, ever.
		if machine.Revoked {
			logger.Warn("Rejected sign-cert for revoked machine", zap.String("machine", machine.Name))
			c.JSON(http.StatusForbidden, gin.H{"error": "machine has been revoked"})
			return
		}

		// Cert fingerprint binding: on renewal the agent sends its current cert fingerprint.
		// If we have a stored fingerprint and it doesn't match, reject — the token is stolen.
		// First-time signing (machine.CertFingerprint == "") is always allowed.
		incomingFP := strings.TrimSpace(c.GetHeader("X-Cert-Fingerprint"))
		if machine.CertFingerprint != "" && incomingFP != "" && machine.CertFingerprint != incomingFP {
			logger.Warn("Cert fingerprint mismatch — possible stolen token",
				zap.String("machine", machine.Name),
				zap.String("stored", machine.CertFingerprint),
				zap.String("incoming", incomingFP))
			c.JSON(http.StatusForbidden, gin.H{"error": "cert fingerprint mismatch"})
			return
		}

		csrPEM, err := io.ReadAll(io.LimitReader(c.Request.Body, 8192))
		if err != nil || len(csrPEM) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing CSR"})
			return
		}

		signedCert, err := caManager.SignCSR(csrPEM)
		if err != nil {
			logger.Error("Failed to sign CSR", zap.Error(err))
			metrics.CertSignsTotal.WithLabelValues("failed").Inc()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to sign cert"})
			return
		}

		// Store the fingerprint of the newly issued cert.
		// Next renewal must present this fingerprint to prove possession of the cert.
		if block, _ := pem.Decode(signedCert); block != nil {
			if leaf, err := x509.ParseCertificate(block.Bytes); err == nil {
				sum := sha256.Sum256(leaf.Raw)
				fp := hex.EncodeToString(sum[:])
				if err := st.UpdateCertFingerprint(token, fp); err != nil {
					logger.Warn("Failed to store cert fingerprint", zap.Error(err))
				}
			}
		}

		logger.Info("Signed agent client cert", zap.String("machine", machine.Name))
		metrics.CertSignsTotal.WithLabelValues("success").Inc()
		c.Data(http.StatusOK, "application/x-pem-file", signedCert)
	})

	// Server cert — kept for backward compat with older agents
	r.GET("/server-cert", func(c *gin.Context) {
		certPEM, err := os.ReadFile(tlsCertFile) // #nosec G304,G703 -- tlsCertFile is a startup config path, not request input
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "cert not found"})
			return
		}
		c.Data(http.StatusOK, "application/x-pem-file", certPEM)
	})

	// CA cert — agents download this to verify server identity and pin trust
	r.GET("/ca-cert", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/x-pem-file", caManager.CertPEM())
	})

	// CA fingerprint — agents poll this every 30 min to detect CA rotation
	r.GET("/ca-fingerprint", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"fingerprint": caManager.Fingerprint()})
	})

	// Agent binary downloads — public, no auth required
	agentBinariesDir := os.Getenv("AGENT_BINARIES_DIR")
	if agentBinariesDir == "" {
		agentBinariesDir = "./agent-binaries"
	}
	r.GET("/agent/download/:filename", func(c *gin.Context) {
		filename := filepath.Base(c.Param("filename"))
		if filename == "." || filename == "" || strings.Contains(filename, "/") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid filename"})
			return
		}
		filePath := filepath.Join(agentBinariesDir, filename)
		if _, err := os.Stat(filePath); os.IsNotExist(err) { // #nosec G703 -- filename already sanitized above (filepath.Base + "/" rejected)
			c.JSON(http.StatusNotFound, gin.H{"error": "package not found: " + filename})
			return
		}
		c.FileAttachment(filePath, filename)
	})

	// All authentication is handled by vsay-auth gateway - no public auth routes needed

	// Protected routes - all routes require vsay-auth authentication
	auth := r.Group("/api")
	auth.Use(h.AuthMiddleware())
	{
		// WebSocket route (requires auth from vsay-auth)
		auth.GET("/terminal/:agent_id/ws", h.TerminalWebSocket)
		// Remote desktop (RDP) WebSocket — Guacamole canvas connects here
		auth.GET("/machines/:agent_id/rdp/ws", h.RDPWebSocket)
		// Downloadable .rdp file — launches a native RDP client (Windows App)
		auth.GET("/machines/:agent_id/rdp/file", h.RDPFile)
		// Live remote-desktop sessions on a machine
		auth.GET("/machines/:agent_id/desktop/sessions", h.DesktopSessions)

		// Remote control — the admin joins the user's live session, with the
		// user's consent, and the whole session is recorded.
		auth.POST("/machines/:agent_id/remote-control/start", h.StartRemoteControl)
		auth.GET("/machines/:agent_id/remote-control/status", h.RemoteControlStatus)
		auth.POST("/machines/:agent_id/remote-control/stop", h.StopRemoteControl)
		auth.GET("/machines/:agent_id/remote-control/ws", h.RemoteControlWebSocket)
		// External SSH/RDP access history + active sessions
		auth.GET("/machines/:agent_id/access-events", h.GetAccessEvents)
		// Dashboard routes
		auth.GET("/dashboard/stats", h.GetDashboardStats)
		auth.GET("/dashboard/recent-machines", h.GetRecentMachines)
		auth.GET("/dashboard/recent-activity", h.GetRecentActivity)

		// Machine routes
		auth.GET("/machines", h.ListMachines)
		auth.POST("/machines", h.CreatePendingMachine)            // Create pending machine with registration token
		auth.GET("/machines/by-id/:machine_id", h.GetMachineByID) // Get machine by MongoDB ID
		auth.GET("/machines/:agent_id", h.GetMachineDetails)
		auth.GET("/machines/:agent_id/logs", h.GetMachineLogs)
		auth.GET("/machines/:agent_id/logs/search", h.SearchMachineLogs)
		auth.GET("/machines/:agent_id/sessions", h.GetMachineSessions)
		auth.GET("/machines/:agent_id/sessions/active", h.GetActiveSessions)
		auth.POST("/machines/:agent_id/command", h.ExecuteCommand)
		auth.DELETE("/machines/:agent_id", h.DeleteMachine)
		auth.POST("/machines/:agent_id/access/grant", h.GrantAccess)
		auth.POST("/machines/:agent_id/access/revoke", h.RevokeAccess)
		auth.GET("/machines/:agent_id/access/users", h.GetMachineAccessUsers)
		auth.POST("/machines/:agent_id/groups/add", h.AddMachineToGroup)
		auth.POST("/machines/:agent_id/groups/remove", h.RemoveMachineFromGroup)

		// Agent self-update
		auth.GET("/machines/:agent_id/update-check", h.CheckAgentUpdate)
		auth.POST("/machines/:agent_id/update", h.UpdateAgent)

		// Session routes
		auth.GET("/sessions/:session_id", h.GetSessionDetails)

		// User management is handled by vsay-auth service

		// Terminal session management routes
		auth.GET("/terminal/sessions", h.ListTerminalSessions)
		auth.DELETE("/terminal/sessions/:session_id", h.DeleteTerminalSession)

		// Profile routes (read-only - management done in vsay-auth)
		auth.GET("/profile", h.GetProfile)

		// Community/Issues routes
		auth.POST("/community/issues", h.CreateIssue)
		auth.GET("/community/issues", h.GetAllIssues)
		auth.GET("/community/issues/:id", h.GetIssueByID)
		auth.PUT("/community/issues/:id", h.UpdateIssue)
		auth.DELETE("/community/issues/:id", h.DeleteIssue)

		// Fixes routes
		auth.POST("/community/issues/:id/fixes", h.CreateFix)
		auth.GET("/community/issues/:id/fixes", h.GetFixesByIssue)
		auth.POST("/community/issues/:id/fixes/:fix_id/like", h.LikeFix)
		auth.DELETE("/community/issues/:id/fixes/:fix_id/like", h.UnlikeFix)
		auth.POST("/community/issues/:id/fixes/:fix_id/accept", h.MarkFixAsAccepted)

		// Image upload
		auth.POST("/community/upload", h.UploadImage)

		// S3 / tenant configuration
		auth.GET("/config/s3", h.GetS3Config)
		auth.POST("/config/s3", h.SaveS3Config)

		// Session recordings
		auth.GET("/machines/:agent_id/recordings", h.GetMachineRecordings)
		auth.GET("/recordings/:id/url", h.GetRecordingURL)

		// Access requests
		auth.POST("/access-requests", h.CreateAccessRequest)
		auth.GET("/access-requests/my", h.GetMyAccessRequests)
		auth.GET("/machines/:agent_id/access-requests", h.GetMachineAccessRequests)
		auth.GET("/machines/:agent_id/pending-requests-count", h.GetPendingRequestsCount)
		auth.POST("/access-requests/:id/approve", h.ApproveAccessRequest)
		auth.POST("/access-requests/:id/reject", h.RejectAccessRequest)

		// Access requests — admin dashboard (sidebar page): list all + revoke,
		// company_admin/super_admin only
		auth.GET("/access-requests", h.AdminOrSuperAdmin(), h.ListAccessRequests)
		auth.POST("/access-requests/:id/revoke", h.AdminOrSuperAdmin(), h.RevokeAccessRequest)

		// Log management — GET visible to admin+super_admin, write ops super_admin only
		logAdminRoutes := auth.Group("/log-management")
		logAdminRoutes.Use(h.AdminOrSuperAdmin())
		{
			logAdminRoutes.GET("/config", h.GetLogManagementConfig)
			logAdminRoutes.GET("/runs", h.GetArchiveRuns)
		}
		logSuperRoutes := auth.Group("/log-management")
		logSuperRoutes.Use(h.SuperAdminOnly())
		{
			logSuperRoutes.POST("/config", h.SaveLogManagementConfig)
			logSuperRoutes.POST("/test-connection", h.TestStorageConnection)
			logSuperRoutes.POST("/archive-now", h.TriggerArchiveNow)
			logSuperRoutes.POST("/runs/:run_id/restore", h.RestoreFromRun)
		}
	}

	// Start services
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// CA rotation loop — checks every 12h, rotates CA when <30 days left,
	// regenerates server cert, prunes expired grace CAs.
	// On rotation, broadcasts new CA PEM to all connected agents over their existing
	// secure gRPC streams so they update without InsecureSkipVerify.
	go caManager.RotationLoop(tlsCertFile, tlsKeyFile, serverDomain, func(newCAPEM []byte) {
		logger.Info("CA rotated — broadcasting new CA to all connected agents")
		agentManager.BroadcastCARotation(string(newCAPEM))
	})

	// Reconciler
	go rec.Start(ctx)

	// Log management reconciler (archival/deletion on schedule)
	logManager := logmgr.NewManager(st, logger)
	logReconciler := logmgr.NewReconciler(logManager, st, logger)
	go logReconciler.Run(ctx)

	// Auto-revoke expired access requests every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				expired, err := st.GetExpiredAccessRequests()
				if err != nil {
					logger.Warn("Failed to get expired access requests", zap.Error(err))
					continue
				}
				for _, ar := range expired {
					if err := st.RevokeMachineAccess(ar.MachineID, ar.RequesterUsername); err != nil {
						logger.Warn("Failed to revoke expired machine access",
							zap.String("request_id", ar.ID.Hex()),
							zap.Error(err))
					}
					ar.Status = "expired"
					if err := st.UpdateAccessRequest(ar); err != nil {
						logger.Warn("Failed to mark access request as expired",
							zap.String("request_id", ar.ID.Hex()),
							zap.Error(err))
					} else {
						logger.Info("Revoked expired machine access",
							zap.String("machine", ar.MachineName),
							zap.String("requester", ar.RequesterUsername))
					}
				}
			}
		}
	}()

	// gRPC
	go func() {
		logger.Info("Starting gRPC server on :8081")
		if err := grpcServer.Serve(lis); err != nil {
			logger.Fatal("Failed to serve gRPC", zap.Error(err))
		}
	}()

	// HTTP/HTTPS Server
	if tlsEnabled {
		srv := &http.Server{
			Addr:              ":" + httpsPort,
			Handler:           r,
			ReadHeaderTimeout: 10 * time.Second,
		}

		go func() {
			logger.Info("Starting HTTPS server", zap.String("port", httpsPort))
			if err := srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile); err != nil && err != http.ErrServerClosed {
				logger.Fatal("Failed to serve HTTPS", zap.Error(err))
			}
		}()

		// Also run HTTP server on 8080 for redirects
		httpSrv := &http.Server{
			Addr:              ":8080",
			ReadHeaderTimeout: 10 * time.Second,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Strip port from host if present
				host := r.Host
				if idx := strings.LastIndex(host, ":"); idx != -1 {
					host = host[:idx]
				}
				// The Host header is attacker-controlled on a raw request (unlike a
				// browser's address bar), so a crafted value could otherwise be
				// reflected straight into the redirect Location. Reject anything
				// that isn't a syntactically plausible hostname instead of
				// forwarding it — legitimate clients always send a well-formed Host.
				if !validRedirectHost.MatchString(host) {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				target := "https://" + host + ":" + httpsPort + r.URL.Path
				if len(r.URL.RawQuery) > 0 {
					target += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, target, http.StatusMovedPermanently) // #nosec G710 -- host is validated against validRedirectHost above; gosec's taint tracker doesn't see through the check
			}),
		}

		go func() {
			logger.Info("Starting HTTP redirect server on :8080")
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Warn("HTTP redirect server error", zap.Error(err))
			}
		}()
	} else {
		srv := &http.Server{
			Addr:              ":8080",
			Handler:           r,
			ReadHeaderTimeout: 10 * time.Second,
		}

		go func() {
			logger.Info("Starting HTTP server on :8080")
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Fatal("Failed to serve HTTP", zap.Error(err))
			}
		}()
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down...")
	grpcServer.GracefulStop()
	// HTTP servers will be cleaned up when context is cancelled
}
