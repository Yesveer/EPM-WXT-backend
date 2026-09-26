package store

import (
	"context"
	"regexp"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDB struct {
	client              *mongo.Client
	db                  *mongo.Database
	Machines            *mongo.Collection
	Logs                *mongo.Collection
	Sessions            *mongo.Collection
	Issues              *mongo.Collection
	Fixes               *mongo.Collection
	TenantConfigs       *mongo.Collection
	Recordings          *mongo.Collection
	LogManagementConfs  *mongo.Collection
	ArchiveRuns         *mongo.Collection
	AuditLogs           *mongo.Collection
	AccessRequests      *mongo.Collection
	AccessEvents        *mongo.Collection
}

func NewMongoDB(uri, dbName string) (*MongoDB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}

	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}

	db := client.Database(dbName)
	store := &MongoDB{
		client:             client,
		db:                 db,
		Machines:           db.Collection("machines"),
		Logs:               db.Collection("logs"),
		Sessions:           db.Collection("sessions"),
		Issues:             db.Collection("issues"),
		Fixes:              db.Collection("fixes"),
		TenantConfigs:      db.Collection("tenant_configs"),
		Recordings:         db.Collection("session_recordings"),
		LogManagementConfs: db.Collection("log_management_config"),
		ArchiveRuns:        db.Collection("archive_runs"),
		AuditLogs:          db.Collection("audit_logs"),
		AccessRequests:     db.Collection("access_requests"),
		AccessEvents:       db.Collection("access_events"),
	}

	// Create indexes
	if err := store.ensureIndexes(ctx); err != nil {
		return nil, err
	}

	return store, nil
}

// ensureIndexes creates necessary database indexes
func (m *MongoDB) ensureIndexes(ctx context.Context) error {
	// User indexes removed - users managed by vsay-auth service

	// Machines indexes
	// Drop old indexes if they exist (to avoid conflicts) — best-effort, the
	// index may simply not exist yet, which is not an error worth surfacing.
	_, _ = m.Machines.Indexes().DropOne(ctx, "agent_id_1")
	_, _ = m.Machines.Indexes().DropOne(ctx, "status_1")

	// Create new indexes
	_, err := m.Machines.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "agent_id", Value: 1}}, Options: options.Index().SetUnique(true).SetSparse(true)},
		{Keys: bson.D{{Key: "owner_id", Value: 1}}},
		{Keys: bson.D{{Key: "status", Value: 1}}},
		{Keys: bson.D{{Key: "registration_token", Value: 1}}, Options: options.Index().SetSparse(true)},
	})
	if err != nil {
		return err
	}

	// Logs indexes - optimized for queries
	_, err = m.Logs.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "machine_id", Value: 1}, {Key: "timestamp", Value: -1}}},
		{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "timestamp", Value: -1}}},
		{Keys: bson.D{{Key: "timestamp", Value: -1}}},
		{Keys: bson.D{{Key: "session_id", Value: 1}, {Key: "timestamp", Value: -1}}},
	})
	if err != nil {
		return err
	}

	// Sessions indexes
	_, err = m.Sessions.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "session_id", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "machine_id", Value: 1}, {Key: "status", Value: 1}}},
		{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "status", Value: 1}}},
		{Keys: bson.D{{Key: "agent_id", Value: 1}, {Key: "status", Value: 1}}},
		{Keys: bson.D{{Key: "created_at", Value: -1}}},
	})
	if err != nil {
		return err
	}

	// TenantConfigs indexes
	_, err = m.TenantConfigs.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "tenant_id", Value: 1}}, Options: options.Index().SetUnique(true)},
	})
	if err != nil {
		return err
	}

	// Recordings indexes
	_, err = m.Recordings.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "machine_id", Value: 1}, {Key: "created_at", Value: -1}}},
		{Keys: bson.D{{Key: "session_id", Value: 1}}},
		{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
	})
	if err != nil {
		return err
	}

	// ArchiveRuns indexes
	_, err = m.ArchiveRuns.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "started_at", Value: -1}}},
		{Keys: bson.D{{Key: "status", Value: 1}}},
	})
	if err != nil {
		return err
	}

	// AuditLogs indexes
	_, err = m.AuditLogs.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "timestamp", Value: -1}}},
		{Keys: bson.D{{Key: "actor_id", Value: 1}}},
		{Keys: bson.D{{Key: "action", Value: 1}}},
	})
	if err != nil {
		return err
	}

	// AccessRequests indexes
	_, err = m.AccessRequests.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "machine_id", Value: 1}, {Key: "status", Value: 1}}},
		{Keys: bson.D{{Key: "requester_id", Value: 1}}},
		{Keys: bson.D{{Key: "expires_at", Value: 1}, {Key: "status", Value: 1}}},
		{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "status", Value: 1}}},
	})
	if err != nil {
		return err
	}

	return nil
}

// User management methods removed - all user data comes from vsay-auth service via headers

// CreatePendingMachine creates a new pending machine with unique registration token
func (m *MongoDB) CreatePendingMachine(machine *Machine) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	machine.CreatedAt = time.Now()
	machine.Status = "pending"
	_, err := m.Machines.InsertOne(ctx, machine)
	return err
}

// GetMachineByRegistrationToken gets a machine by its registration token
func (m *MongoDB) GetMachineByRegistrationToken(token string) (*Machine, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var machine Machine
	err := m.Machines.FindOne(ctx, bson.M{"registration_token": token}).Decode(&machine)
	if err != nil {
		return nil, err
	}
	return &machine, nil
}

// RevokeMachine marks a machine as revoked — blocks future cert signing and gRPC registration.
// The agent's live gRPC connection is kicked separately by the caller (via AgentManager).
func (m *MongoDB) RevokeMachine(machineID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	_, err := m.Machines.UpdateOne(ctx,
		bson.M{"_id": machineID},
		bson.M{"$set": bson.M{
			"revoked":    true,
			"revoked_at": now,
			"status":     "revoked",
		}},
	)
	return err
}

// UpdateCertFingerprint stores the SHA-256 fingerprint of the most recently issued agent cert.
// Used to bind the registration token to a specific cert, so a leaked token alone is useless.
func (m *MongoDB) UpdateCertFingerprint(token, fingerprint string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Machines.UpdateOne(ctx,
		bson.M{"registration_token": token},
		bson.M{"$set": bson.M{"cert_fingerprint": fingerprint}},
	)
	return err
}

// GetMachineByName gets a machine by name for a specific owner (for uniqueness check)
func (m *MongoDB) GetMachineByName(name string, ownerID primitive.ObjectID) (*Machine, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var machine Machine
	err := m.Machines.FindOne(ctx, bson.M{
		"name":     name,
		"owner_id": ownerID,
	}).Decode(&machine)
	if err != nil {
		return nil, err
	}
	return &machine, nil
}

// ActivateMachine activates a pending machine when agent connects
func (m *MongoDB) ActivateMachine(token string, agentID string, osInfo string, ipAddress string, metadata map[string]string, initialStatus string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if initialStatus == "" {
		initialStatus = "online"
	}

	_, err := m.Machines.UpdateOne(ctx,
		bson.M{"registration_token": token},
		bson.M{"$set": bson.M{
			"agent_id":    agentID,
			"os":          osInfo,
			"ip_address":  ipAddress,
			"status":      initialStatus,
			"last_active": time.Now(),
			"metadata":    metadata,
		}},
	)
	return err
}

func (m *MongoDB) RegisterMachine(machine *Machine) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if already exists by AgentID
	filter := bson.M{"agent_id": machine.AgentID}

	// Use $setOnInsert for fields that should only be set on creation
	// and $set for fields that should always be updated
	update := bson.M{
		"$set": bson.M{
			"name":           machine.Name,
			"description":    machine.Description,
			"os":             machine.OS,
			"ip_address":     machine.IPAddress,
			"status":         machine.Status,
			"last_active":    machine.LastActive,
			"uptime":         machine.Uptime,
			"resource_stats": machine.ResourceStats,
			"metadata":       machine.Metadata,
		},
		"$setOnInsert": bson.M{
			"owner_id":      machine.OwnerID,
			"tenant_id":     machine.TenantID,
			"org_id":        machine.OrgID,
			"group_ids":     machine.GroupIDs,
			"allowed_users": machine.AllowedUsers,
		},
	}
	opts := options.Update().SetUpsert(true)

	_, err := m.Machines.UpdateOne(ctx, filter, update, opts)
	return err
}

func (m *MongoDB) GetMachineByAgentID(agentID string) (*Machine, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var machine Machine
	err := m.Machines.FindOne(ctx, bson.M{"agent_id": agentID}).Decode(&machine)
	if err != nil {
		return nil, err
	}
	return &machine, nil
}

// GetMachineByID gets a machine by its MongoDB ObjectID
func (m *MongoDB) GetMachineByID(machineID primitive.ObjectID) (*Machine, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var machine Machine
	err := m.Machines.FindOne(ctx, bson.M{"_id": machineID}).Decode(&machine)
	if err != nil {
		return nil, err
	}
	return &machine, nil
}

func (m *MongoDB) GetMachinesByOwner(ownerID primitive.ObjectID) ([]*Machine, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := m.Machines.Find(ctx, bson.M{"owner_id": ownerID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var machines []*Machine
	if err := cursor.All(ctx, &machines); err != nil {
		return nil, err
	}
	return machines, nil
}

func (m *MongoDB) GetAllMachines() ([]*Machine, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := m.Machines.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var machines []*Machine
	if err := cursor.All(ctx, &machines); err != nil {
		return nil, err
	}
	return machines, nil
}

func (m *MongoDB) GetMachinesByTenantID(tenantID string) ([]*Machine, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := m.Machines.Find(ctx, bson.M{"tenant_id": tenantID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var machines []*Machine
	if err := cursor.All(ctx, &machines); err != nil {
		return nil, err
	}
	return machines, nil
}

func (m *MongoDB) MarkInactiveMachinesOffline(inactiveThreshold time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cutoffTime := time.Now().Add(-inactiveThreshold)

	// Update machines that are marked as "online" but haven't been active recently
	_, err := m.Machines.UpdateMany(ctx,
		bson.M{
			"status":      "online",
			"last_active": bson.M{"$lt": cutoffTime},
		},
		bson.M{
			"$set": bson.M{
				"status": "offline",
			},
		},
	)

	return err
}

// MarkAllMachinesOffline flips every "online" machine to "offline". Used on
// backend startup so stale "online" statuses from a killed previous process don't
// linger until the reconciler timeout. Live agents reconnect within seconds.
func (m *MongoDB) MarkAllMachinesOffline() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Machines.UpdateMany(ctx,
		bson.M{"status": "online"},
		bson.M{"$set": bson.M{"status": "offline"}},
	)
	return err
}

// CountMachinesByStatus returns per-status counts using the status index.
// Each CountDocuments call is an index-only scan — does NOT load full documents.
// Use this in the reconciler instead of GetAllMachines().
func (m *MongoDB) CountMachinesByStatus() (online, offline, pending int64, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	online, err = m.Machines.CountDocuments(ctx, bson.M{"status": "online"})
	if err != nil {
		return
	}
	offline, err = m.Machines.CountDocuments(ctx, bson.M{"status": "offline"})
	if err != nil {
		return
	}
	pending, err = m.Machines.CountDocuments(ctx, bson.M{"status": "pending"})
	return
}

func (m *MongoDB) UpdateMachineStatus(agentID string, status string, lastActive time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Machines.UpdateOne(ctx,
		bson.M{"agent_id": agentID},
		bson.M{"$set": bson.M{
			"status":      status,
			"last_active": lastActive,
		}},
	)
	return err
}

func (m *MongoDB) UpdateMachineStats(agentID string, stats ResourceStats) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Machines.UpdateOne(ctx,
		bson.M{"agent_id": agentID},
		bson.M{"$set": bson.M{
			"resource_stats": stats,
			"uptime":         stats.Uptime,
		}},
	)
	return err
}

// UpdateMachineHeartbeat writes status + stats in a single MongoDB round-trip.
// Replaces calling UpdateMachineStatus + UpdateMachineStats separately — halves
// the MongoDB write load from heartbeats (2 writes/30s/agent → 1 write/30s/agent).
func (m *MongoDB) UpdateMachineHeartbeat(agentID string, lastActive time.Time, stats ResourceStats) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Machines.UpdateOne(ctx,
		bson.M{"agent_id": agentID},
		bson.M{"$set": bson.M{
			"status":         "online",
			"last_active":    lastActive,
			"resource_stats": stats,
			"uptime":         stats.Uptime,
		}},
	)
	return err
}

func (m *MongoDB) CreateLog(log *LogEntry) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Timestamp = time.Now()
	result, err := m.Logs.InsertOne(ctx, log)
	if err != nil {
		return err
	}
	if oid, ok := result.InsertedID.(primitive.ObjectID); ok {
		log.ID = oid
	}
	return nil
}

func (m *MongoDB) UpdateLogOutput(logID primitive.ObjectID, output string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Logs.UpdateOne(ctx,
		bson.M{"_id": logID},
		bson.M{"$set": bson.M{"output": output}},
	)
	return err
}

func (m *MongoDB) GetLogsByMachine(machineID primitive.ObjectID, limit int) ([]*LogEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.M{"timestamp": -1}).SetLimit(int64(limit))
	cursor, err := m.Logs.Find(ctx, bson.M{"machine_id": machineID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []*LogEntry
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	return logs, nil
}

func (m *MongoDB) GetLogsByMachinePaged(machineID primitive.ObjectID, limit, skip int) ([]*LogEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetLimit(int64(limit)).
		SetSkip(int64(skip))
	cursor, err := m.Logs.Find(ctx, bson.M{"machine_id": machineID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []*LogEntry
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	return logs, nil
}

func (m *MongoDB) CountLogsByMachine(machineID primitive.ObjectID) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return m.Logs.CountDocuments(ctx, bson.M{"machine_id": machineID})
}

func (m *MongoDB) GetLogsBySessionPaged(sessionID string, limit, skip int) ([]*LogEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// ASC order (oldest first) for session replay — terminal output must be in sequence
	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: 1}}).
		SetLimit(int64(limit)).
		SetSkip(int64(skip))
	cursor, err := m.Logs.Find(ctx, bson.M{"session_id": sessionID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []*LogEntry
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	return logs, nil
}

func (m *MongoDB) CountLogsBySession(sessionID string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return m.Logs.CountDocuments(ctx, bson.M{"session_id": sessionID})
}

func (m *MongoDB) SearchLogsByMachinePaged(machineID primitive.ObjectID, query string, limit, skip int) ([]*LogEntry, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"machine_id": machineID}
	if query != "" {
		filter["command"] = bson.M{"$regex": query, "$options": "i"}
	}

	total, err := m.Logs.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetLimit(int64(limit)).
		SetSkip(int64(skip))
	cursor, err := m.Logs.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)

	var logs []*LogEntry
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

func (m *MongoDB) GetSessionsByMachinePaged(machineID primitive.ObjectID, limit, skip int) ([]*Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().
		SetSort(bson.D{{Key: "created_at", Value: -1}}).
		SetLimit(int64(limit)).
		SetSkip(int64(skip))
	cursor, err := m.Sessions.Find(ctx, bson.M{"machine_id": machineID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var sessions []*Session
	if err := cursor.All(ctx, &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

func (m *MongoDB) CountSessionsByMachine(machineID primitive.ObjectID) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return m.Sessions.CountDocuments(ctx, bson.M{"machine_id": machineID})
}

// GetDashboardStats returns dashboard statistics
func (m *MongoDB) GetDashboardStats(ownerID primitive.ObjectID) (*DashboardStats, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Total machines
	totalMachines, err := m.Machines.CountDocuments(ctx, bson.M{"owner_id": ownerID})
	if err != nil {
		return nil, err
	}

	// Active machines (online)
	activeMachines, err := m.Machines.CountDocuments(ctx, bson.M{
		"owner_id": ownerID,
		"status":   "online",
	})
	if err != nil {
		return nil, err
	}

	// Inactive machines (offline)
	inactiveMachines := totalMachines - activeMachines

	// Total sessions (count from logs or you can add a sessions collection)
	totalSessions, err := m.Logs.CountDocuments(ctx, bson.M{})
	if err != nil {
		totalSessions = 0
	}

	return &DashboardStats{
		TotalMachines:    int(totalMachines),
		ActiveMachines:   int(activeMachines),
		InactiveMachines: int(inactiveMachines),
		TotalSessions:    int(totalSessions),
	}, nil
}

// GetRecentMachines returns recently active machines
func (m *MongoDB) GetRecentMachines(ownerID primitive.ObjectID, limit int) ([]*Machine, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().
		SetSort(bson.M{"last_active": -1}).
		SetLimit(int64(limit))

	cursor, err := m.Machines.Find(ctx, bson.M{"owner_id": ownerID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var machines []*Machine
	if err := cursor.All(ctx, &machines); err != nil {
		return nil, err
	}
	return machines, nil
}

// GetRecentActivity returns recent activity logs
func (m *MongoDB) GetRecentActivity(ownerID primitive.ObjectID, limit int) ([]*ActivityLog, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get user's machines first
	machines, err := m.GetMachinesByOwner(ownerID)
	if err != nil {
		return nil, err
	}

	// Extract machine IDs
	machineIDs := make([]primitive.ObjectID, 0, len(machines))
	machineMap := make(map[primitive.ObjectID]*Machine)
	for _, machine := range machines {
		machineIDs = append(machineIDs, machine.ID)
		machineMap[machine.ID] = machine
	}

	// Get recent logs for these machines
	opts := options.Find().
		SetSort(bson.M{"timestamp": -1}).
		SetLimit(int64(limit))

	cursor, err := m.Logs.Find(ctx, bson.M{
		"machine_id": bson.M{"$in": machineIDs},
	}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []*LogEntry
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}

	// Convert to activity logs with machine info
	activities := make([]*ActivityLog, 0, len(logs))
	for _, log := range logs {
		machine := machineMap[log.MachineID]
		machineName := "Unknown"
		if machine != nil {
			machineName = machine.Name
		}

		activities = append(activities, &ActivityLog{
			ID:          log.ID,
			MachineID:   log.MachineID,
			MachineName: machineName,
			Command:     log.Command,
			Success:     log.Success,
			Timestamp:   log.Timestamp,
		})
	}

	return activities, nil
}

// User methods removed - user data comes from vsay-auth service

// GetMachinesSharedWithUser gets machines where user has access
func (m *MongoDB) GetMachinesSharedWithUser(username string) ([]*Machine, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := m.Machines.Find(ctx, bson.M{
		"allowed_users": username,
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var machines []*Machine
	if err := cursor.All(ctx, &machines); err != nil {
		return nil, err
	}

	return machines, nil
}

// DeleteMachine deletes a machine and all associated logs
func (m *MongoDB) DeleteMachine(machineID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Delete the machine
	_, err := m.Machines.DeleteOne(ctx, bson.M{"_id": machineID})
	if err != nil {
		return err
	}

	// Delete all logs for this machine
	_, err = m.Logs.DeleteMany(ctx, bson.M{"machine_id": machineID})
	return err
}

// DeleteLogsByMachine deletes all logs for a specific machine
func (m *MongoDB) DeleteLogsByMachine(machineID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Logs.DeleteMany(ctx, bson.M{"machine_id": machineID})
	return err
}

// GrantMachineAccess adds a user to the allowed users list
func (m *MongoDB) GrantMachineAccess(machineID primitive.ObjectID, username string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First ensure allowed_users field exists and is an array (handle null or missing)
	_, err := m.Machines.UpdateOne(ctx,
		bson.M{
			"_id": machineID,
			"$or": []bson.M{
				{"allowed_users": bson.M{"$exists": false}},
				{"allowed_users": nil},
			},
		},
		bson.M{"$set": bson.M{"allowed_users": []string{}}},
	)
	// Ignore error if field already exists and is an array

	// Add username to allowed_users array (no duplicates)
	_, err = m.Machines.UpdateOne(ctx,
		bson.M{"_id": machineID},
		bson.M{"$addToSet": bson.M{"allowed_users": username}},
	)
	return err
}

// RevokeMachineAccess removes a user from the allowed users list
func (m *MongoDB) RevokeMachineAccess(machineID primitive.ObjectID, username string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Remove username from allowed_users array
	_, err := m.Machines.UpdateOne(ctx,
		bson.M{"_id": machineID},
		bson.M{"$pull": bson.M{"allowed_users": username}},
	)
	return err
}

// AddMachineToGroup adds a group ID to the machine's group_ids array
func (m *MongoDB) AddMachineToGroup(agentID string, groupID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First ensure group_ids field exists and is an array (handle null or missing)
	_, err := m.Machines.UpdateOne(ctx,
		bson.M{
			"agent_id": agentID,
			"$or": []bson.M{
				{"group_ids": bson.M{"$exists": false}},
				{"group_ids": nil},
			},
		},
		bson.M{"$set": bson.M{"group_ids": []string{}}},
	)
	// Ignore error if field already exists and is an array

	// Add groupID to group_ids array (no duplicates)
	_, err = m.Machines.UpdateOne(ctx,
		bson.M{"agent_id": agentID},
		bson.M{"$addToSet": bson.M{"group_ids": groupID}},
	)
	return err
}

// RemoveMachineFromGroup removes a group ID from the machine's group_ids array
func (m *MongoDB) RemoveMachineFromGroup(agentID string, groupID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Remove groupID from group_ids array
	_, err := m.Machines.UpdateOne(ctx,
		bson.M{"agent_id": agentID},
		bson.M{"$pull": bson.M{"group_ids": groupID}},
	)
	return err
}

// ===== Community/Issues Methods =====

// CreateIssue creates a new issue
func (m *MongoDB) CreateIssue(issue *Issue) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	issue.CreatedAt = time.Now()
	issue.UpdatedAt = time.Now()
	issue.FixCount = 0

	result, err := m.Issues.InsertOne(ctx, issue)
	if err != nil {
		return err
	}

	issue.ID = result.InsertedID.(primitive.ObjectID)
	return nil
}

// GetIssueByID gets an issue by ID
func (m *MongoDB) GetIssueByID(issueID primitive.ObjectID) (*Issue, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var issue Issue
	err := m.Issues.FindOne(ctx, bson.M{"_id": issueID}).Decode(&issue)
	if err != nil {
		return nil, err
	}
	return &issue, nil
}

// GetAllIssues gets all issues with pagination
func (m *MongoDB) GetAllIssues(limit, skip int) ([]*Issue, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().
		SetSort(bson.M{"created_at": -1}).
		SetLimit(int64(limit)).
		SetSkip(int64(skip))

	cursor, err := m.Issues.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var issues []*Issue
	if err := cursor.All(ctx, &issues); err != nil {
		return nil, err
	}
	return issues, nil
}

// UpdateIssue updates an issue with given fields
func (m *MongoDB) UpdateIssue(issueID primitive.ObjectID, updates map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	updates["updated_at"] = time.Now()

	_, err := m.Issues.UpdateOne(ctx,
		bson.M{"_id": issueID},
		bson.M{"$set": updates},
	)
	return err
}

// DeleteIssue deletes an issue and all associated fixes
func (m *MongoDB) DeleteIssue(issueID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Delete the issue
	_, err := m.Issues.DeleteOne(ctx, bson.M{"_id": issueID})
	if err != nil {
		return err
	}

	// Delete all fixes for this issue
	_, err = m.Fixes.DeleteMany(ctx, bson.M{"issue_id": issueID})
	return err
}

// IncrementIssueFixCount increments the fix count for an issue
func (m *MongoDB) IncrementIssueFixCount(issueID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Issues.UpdateOne(ctx,
		bson.M{"_id": issueID},
		bson.M{"$inc": bson.M{"fix_count": 1}},
	)
	return err
}

// ===== Fixes Methods =====

// CreateFix creates a new fix for an issue
func (m *MongoDB) CreateFix(fix *Fix) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fix.CreatedAt = time.Now()
	fix.Likes = 0
	fix.LikedBy = []string{}
	fix.IsAccepted = false

	result, err := m.Fixes.InsertOne(ctx, fix)
	if err != nil {
		return err
	}

	fix.ID = result.InsertedID.(primitive.ObjectID)

	// Increment issue fix count
	return m.IncrementIssueFixCount(fix.IssueID)
}

// GetFixesByIssue gets all fixes for an issue
func (m *MongoDB) GetFixesByIssue(issueID primitive.ObjectID) ([]*Fix, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.M{"created_at": -1})
	cursor, err := m.Fixes.Find(ctx, bson.M{"issue_id": issueID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var fixes []*Fix
	if err := cursor.All(ctx, &fixes); err != nil {
		return nil, err
	}
	return fixes, nil
}

// GetFixByID gets a fix by ID
func (m *MongoDB) GetFixByID(fixID primitive.ObjectID) (*Fix, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var fix Fix
	err := m.Fixes.FindOne(ctx, bson.M{"_id": fixID}).Decode(&fix)
	if err != nil {
		return nil, err
	}
	return &fix, nil
}

// UpdateFix updates a fix with given fields
func (m *MongoDB) UpdateFix(fixID primitive.ObjectID, updates map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Fixes.UpdateOne(ctx,
		bson.M{"_id": fixID},
		bson.M{"$set": updates},
	)
	return err
}

// DeleteFix deletes a fix
func (m *MongoDB) DeleteFix(fixID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Fixes.DeleteOne(ctx, bson.M{"_id": fixID})
	return err
}

// LikeFix adds a username to the liked_by array and increments likes
func (m *MongoDB) LikeFix(fixID primitive.ObjectID, username string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Fixes.UpdateOne(ctx,
		bson.M{"_id": fixID},
		bson.M{
			"$addToSet": bson.M{"liked_by": username},
			"$inc":      bson.M{"likes": 1},
		},
	)
	return err
}

// UnlikeFix removes a username from the liked_by array and decrements likes
func (m *MongoDB) UnlikeFix(fixID primitive.ObjectID, username string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Fixes.UpdateOne(ctx,
		bson.M{"_id": fixID},
		bson.M{
			"$pull": bson.M{"liked_by": username},
			"$inc":  bson.M{"likes": -1},
		},
	)
	return err
}

// MarkFixAsAccepted marks a fix as accepted and unmarks all others for that issue
func (m *MongoDB) MarkFixAsAccepted(fixID primitive.ObjectID, issueID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First, unmark all fixes for this issue
	_, err := m.Fixes.UpdateMany(ctx,
		bson.M{"issue_id": issueID},
		bson.M{"$set": bson.M{"is_accepted": false}},
	)
	if err != nil {
		return err
	}

	// Mark the specific fix as accepted
	_, err = m.Fixes.UpdateOne(ctx,
		bson.M{"_id": fixID},
		bson.M{"$set": bson.M{"is_accepted": true}},
	)
	return err
}

// ===== Session Methods =====

// CreateSession creates a new terminal session
func (m *MongoDB) CreateSession(session *Session) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session.CreatedAt = time.Now()
	session.Status = "active"
	session.CommandCount = 0

	result, err := m.Sessions.InsertOne(ctx, session)
	if err != nil {
		return err
	}

	session.ID = result.InsertedID.(primitive.ObjectID)
	return nil
}

// GetSessionByID gets a session by its session_id string
func (m *MongoDB) GetSessionByID(sessionID string) (*Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var session Session
	err := m.Sessions.FindOne(ctx, bson.M{"session_id": sessionID}).Decode(&session)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// GetSessionsByMachine gets all sessions for a machine
func (m *MongoDB) GetSessionsByMachine(machineID primitive.ObjectID) ([]*Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.M{"created_at": -1})
	cursor, err := m.Sessions.Find(ctx, bson.M{"machine_id": machineID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var sessions []*Session
	if err := cursor.All(ctx, &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

// GetActiveSessionsByMachine gets active sessions for a machine
func (m *MongoDB) GetActiveSessionsByMachine(machineID primitive.ObjectID) ([]*Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.M{"created_at": -1})
	cursor, err := m.Sessions.Find(ctx, bson.M{
		"machine_id": machineID,
		"status":     "active",
	}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var sessions []*Session
	if err := cursor.All(ctx, &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

// GetSessionsByUser gets all sessions for a user
func (m *MongoDB) GetSessionsByUser(userID primitive.ObjectID) ([]*Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.M{"created_at": -1})
	cursor, err := m.Sessions.Find(ctx, bson.M{"user_id": userID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var sessions []*Session
	if err := cursor.All(ctx, &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

// UpdateSessionStatus updates session status
func (m *MongoDB) UpdateSessionStatus(sessionID string, status string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Sessions.UpdateOne(ctx,
		bson.M{"session_id": sessionID},
		bson.M{"$set": bson.M{"status": status}},
	)
	return err
}

// CloseSession marks a session as closed
func (m *MongoDB) CloseSession(sessionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	_, err := m.Sessions.UpdateOne(ctx,
		bson.M{"session_id": sessionID},
		bson.M{"$set": bson.M{
			"status":    "closed",
			"closed_at": now,
		}},
	)
	return err
}

// IncrementSessionCommandCount increments command count for a session
func (m *MongoDB) IncrementSessionCommandCount(sessionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Sessions.UpdateOne(ctx,
		bson.M{"session_id": sessionID},
		bson.M{"$inc": bson.M{"command_count": 1}},
	)
	return err
}

// GetLogsBySession gets all logs for a specific session
func (m *MongoDB) GetLogsBySession(sessionID string) ([]*LogEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.M{"timestamp": -1})
	cursor, err := m.Logs.Find(ctx, bson.M{"session_id": sessionID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []*LogEntry
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	return logs, nil
}

// ========== TenantConfig Operations ==========

func (m *MongoDB) GetTenantConfig(tenantID string) (*TenantConfig, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var cfg TenantConfig
	err := m.TenantConfigs.FindOne(ctx, bson.M{"tenant_id": tenantID}).Decode(&cfg)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// Return empty config with defaults
			return &TenantConfig{TenantID: tenantID}, nil
		}
		return nil, err
	}
	return &cfg, nil
}

func (m *MongoDB) UpsertTenantConfig(cfg *TenantConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg.UpdatedAt = time.Now()
	_, err := m.TenantConfigs.UpdateOne(
		ctx,
		bson.M{"tenant_id": cfg.TenantID},
		bson.M{"$set": cfg},
		options.Update().SetUpsert(true),
	)
	return err
}

// ========== SessionRecording Operations ==========

func (m *MongoDB) CreateRecording(recording *SessionRecording) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	recording.CreatedAt = time.Now()
	result, err := m.Recordings.InsertOne(ctx, recording)
	if err != nil {
		return err
	}
	recording.ID = result.InsertedID.(primitive.ObjectID)
	return nil
}

func (m *MongoDB) GetRecordingsByMachine(machineID primitive.ObjectID, limit, skip int) ([]*SessionRecording, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().
		SetSort(bson.D{{Key: "created_at", Value: -1}}).
		SetLimit(int64(limit)).
		SetSkip(int64(skip))

	cursor, err := m.Recordings.Find(ctx, bson.M{"machine_id": machineID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var recordings []*SessionRecording
	if err := cursor.All(ctx, &recordings); err != nil {
		return nil, err
	}
	return recordings, nil
}

func (m *MongoDB) CountRecordingsByMachine(machineID primitive.ObjectID) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return m.Recordings.CountDocuments(ctx, bson.M{"machine_id": machineID})
}

func (m *MongoDB) GetRecordingByID(id primitive.ObjectID) (*SessionRecording, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var recording SessionRecording
	err := m.Recordings.FindOne(ctx, bson.M{"_id": id}).Decode(&recording)
	if err != nil {
		return nil, err
	}
	return &recording, nil
}

func (m *MongoDB) Ping(ctx context.Context) error {
	return m.client.Ping(ctx, nil)
}

// ── Log Management ────────────────────────────────────────────────────────────

func (m *MongoDB) GetLogManagementConfig() (*LogManagementConfig, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var cfg LogManagementConfig
	err := m.LogManagementConfs.FindOne(ctx, bson.M{}).Decode(&cfg)
	if err == mongo.ErrNoDocuments {
		return &LogManagementConfig{RetentionDays: 30, ArchiveEnabled: false, ArchiveEveryDays: 30}, nil
	}
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (m *MongoDB) UpsertLogManagementConfig(cfg *LogManagementConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg.UpdatedAt = time.Now()
	_, err := m.LogManagementConfs.ReplaceOne(ctx, bson.M{}, cfg, options.Replace().SetUpsert(true))
	return err
}

func (m *MongoDB) GetLogsOlderThan(before time.Time, limit int) ([]*LogEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: 1}}).SetLimit(int64(limit))
	cursor, err := m.Logs.Find(ctx, bson.M{"timestamp": bson.M{"$lt": before}}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var logs []*LogEntry
	return logs, cursor.All(ctx, &logs)
}

func (m *MongoDB) DeleteLogsByIDs(ids []primitive.ObjectID) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := m.Logs.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": ids}})
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}

func (m *MongoDB) GetSessionsOlderThan(before time.Time, limit int) ([]*Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	filter := bson.M{"created_at": bson.M{"$lt": before}, "status": "closed"}
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}}).SetLimit(int64(limit))
	cursor, err := m.Sessions.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var sessions []*Session
	return sessions, cursor.All(ctx, &sessions)
}

func (m *MongoDB) DeleteSessionsByIDs(ids []primitive.ObjectID) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := m.Sessions.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": ids}})
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}

func (m *MongoDB) GetAuditLogsOlderThan(before time.Time, limit int) ([]*AuditLog, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	filter := bson.M{"timestamp": bson.M{"$lt": before}}
	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: 1}}).SetLimit(int64(limit))
	cursor, err := m.AuditLogs.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var logs []*AuditLog
	return logs, cursor.All(ctx, &logs)
}

func (m *MongoDB) DeleteAuditLogsByIDs(ids []primitive.ObjectID) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := m.AuditLogs.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": ids}})
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}

func (m *MongoDB) CreateAuditLog(log *AuditLog) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now()
	}
	result, err := m.AuditLogs.InsertOne(ctx, log)
	if err != nil {
		return err
	}
	log.ID = result.InsertedID.(primitive.ObjectID)
	return nil
}

func (m *MongoDB) CreateArchiveRun(run *ArchiveRun) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := m.ArchiveRuns.InsertOne(ctx, run)
	if err != nil {
		return err
	}
	run.ID = result.InsertedID.(primitive.ObjectID)
	return nil
}

func (m *MongoDB) GetArchiveRuns(limit int) ([]*ArchiveRun, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	opts := options.Find().SetSort(bson.D{{Key: "started_at", Value: -1}}).SetLimit(int64(limit))
	cursor, err := m.ArchiveRuns.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var runs []*ArchiveRun
	return runs, cursor.All(ctx, &runs)
}

func (m *MongoDB) GetArchiveRunByID(id primitive.ObjectID) (*ArchiveRun, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var run ArchiveRun
	err := m.ArchiveRuns.FindOne(ctx, bson.M{"_id": id}).Decode(&run)
	if err != nil {
		return nil, err
	}
	return &run, nil
}

func (m *MongoDB) UpdateArchiveRunFinished(id primitive.ObjectID, status, errMsg string, logsArchived, sessionsArchived, logsDeleted, bytesArchived int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now()
	_, err := m.ArchiveRuns.UpdateOne(ctx, bson.M{"_id": id}, bson.M{
		"$set": bson.M{
			"finished_at": &now, "status": status, "error_msg": errMsg,
			"logs_archived": logsArchived, "sessions_archived": sessionsArchived,
			"logs_deleted": logsDeleted, "bytes_archived": bytesArchived,
		},
	})
	return err
}

// ========== AccessRequest Operations ==========

func (m *MongoDB) CreateAccessRequest(req *AccessRequest) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	req.RequestedAt = now
	req.UpdatedAt = now

	result, err := m.AccessRequests.InsertOne(ctx, req)
	if err != nil {
		return err
	}
	req.ID = result.InsertedID.(primitive.ObjectID)
	return nil
}

func (m *MongoDB) GetAccessRequestsByMachine(machineID primitive.ObjectID) ([]*AccessRequest, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.D{{Key: "requested_at", Value: -1}})
	cursor, err := m.AccessRequests.Find(ctx, bson.M{"machine_id": machineID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var reqs []*AccessRequest
	return reqs, cursor.All(ctx, &reqs)
}

func (m *MongoDB) GetAccessRequestsByRequester(requesterID, tenantID string) ([]*AccessRequest, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"requester_id": requesterID, "tenant_id": tenantID}
	opts := options.Find().SetSort(bson.D{{Key: "requested_at", Value: -1}})
	cursor, err := m.AccessRequests.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var reqs []*AccessRequest
	return reqs, cursor.All(ctx, &reqs)
}

func (m *MongoDB) GetAccessRequestByID(id primitive.ObjectID) (*AccessRequest, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var req AccessRequest
	err := m.AccessRequests.FindOne(ctx, bson.M{"_id": id}).Decode(&req)
	if err != nil {
		return nil, err
	}
	return &req, nil
}

func (m *MongoDB) UpdateAccessRequest(req *AccessRequest) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req.UpdatedAt = time.Now()
	_, err := m.AccessRequests.ReplaceOne(ctx, bson.M{"_id": req.ID}, req)
	return err
}

func (m *MongoDB) GetAccessRequestsFiltered(tenantID, status, search string, limit, skip int) ([]*AccessRequest, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"status": status}
	if tenantID != "" {
		filter["tenant_id"] = tenantID
	}
	if search != "" {
		re := primitive.Regex{Pattern: regexp.QuoteMeta(search), Options: "i"}
		filter["$or"] = []bson.M{
			{"requester_username": re},
			{"requester_email": re},
			{"machine_name": re},
		}
	}

	total, err := m.AccessRequests.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	opts := options.Find().
		SetSort(bson.D{{Key: "updated_at", Value: -1}}).
		SetSkip(int64(skip)).
		SetLimit(int64(limit))
	cursor, err := m.AccessRequests.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)

	var reqs []*AccessRequest
	if err := cursor.All(ctx, &reqs); err != nil {
		return nil, 0, err
	}
	return reqs, total, nil
}

func (m *MongoDB) GetExpiredAccessRequests() ([]*AccessRequest, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{
		"status":     "approved",
		"expires_at": bson.M{"$lt": time.Now()},
	}
	opts := options.Find().SetSort(bson.D{{Key: "expires_at", Value: 1}})
	cursor, err := m.AccessRequests.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var reqs []*AccessRequest
	return reqs, cursor.All(ctx, &reqs)
}

// ---- External access events (SSH/RDP intrusion tracking) ----

func (m *MongoDB) CreateAccessEvent(ev *AccessEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now()
	}
	result, err := m.AccessEvents.InsertOne(ctx, ev)
	if err != nil {
		return err
	}
	ev.ID = result.InsertedID.(primitive.ObjectID)
	return nil
}

// CloseAccessEvent marks the most recent active session for (agentID, osUser, line)
// as logged out. Matches on the dedup key the agent reports.
func (m *MongoDB) CloseAccessEvent(agentID, osUser, line string, logoutAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"agent_id": agentID, "os_user": osUser, "line": line, "active": true}
	update := bson.M{"$set": bson.M{"active": false, "logout_at": logoutAt}}
	opts := options.FindOneAndUpdate().SetSort(bson.D{{Key: "login_at", Value: -1}})
	return m.AccessEvents.FindOneAndUpdate(ctx, filter, update, opts).Err()
}

func (m *MongoDB) GetActiveAccessEvents(machineID primitive.ObjectID) ([]*AccessEvent, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.D{{Key: "login_at", Value: -1}})
	cursor, err := m.AccessEvents.Find(ctx, bson.M{"machine_id": machineID, "active": true}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	events := []*AccessEvent{}
	return events, cursor.All(ctx, &events)
}

func (m *MongoDB) GetAccessEventsByMachine(machineID primitive.ObjectID, limit, skip int) ([]*AccessEvent, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.D{{Key: "login_at", Value: -1}}).SetLimit(int64(limit)).SetSkip(int64(skip))
	cursor, err := m.AccessEvents.Find(ctx, bson.M{"machine_id": machineID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	events := []*AccessEvent{}
	return events, cursor.All(ctx, &events)
}

func (m *MongoDB) CountAccessEventsByMachine(machineID primitive.ObjectID) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return m.AccessEvents.CountDocuments(ctx, bson.M{"machine_id": machineID})
}

// AddMachineNotifyEmail adds an email to the machine's intrusion-alert recipient set.
func (m *MongoDB) AddMachineNotifyEmail(machineID primitive.ObjectID, email string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := m.Machines.UpdateOne(ctx,
		bson.M{"_id": machineID},
		bson.M{"$addToSet": bson.M{"notify_emails": email}})
	return err
}

// UpsertAgentStats stores the agent process's latest resource usage on the machine.
func (m *MongoDB) UpsertAgentStats(agentID string, stats *AgentStats) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stats.UpdatedAt = time.Now()
	_, err := m.Machines.UpdateOne(ctx,
		bson.M{"agent_id": agentID},
		bson.M{"$set": bson.M{"agent_stats": stats}})
	return err
}
