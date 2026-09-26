package logmanager

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	s3client "github.com/vsay/vsay-agent-backend/internal/s3"
	"github.com/vsay/vsay-agent-backend/internal/store"
)

// ── Archive file format ───────────────────────────────────────────────────────

// ArchiveRecord wraps a log or session with a type discriminator for NDJSON.
type ArchiveRecord struct {
	Type    string          `json:"_type"` // "log" or "session"
	Payload json.RawMessage `json:"payload"`
}

// BuildArchiveKey returns the storage key for an archive at time t.
func BuildArchiveKey(prefix string, t time.Time) string {
	if prefix == "" {
		prefix = "vsay-logs"
	}
	return fmt.Sprintf("%s/archive-%s.ndjson.gz",
		strings.TrimRight(prefix, "/"),
		t.UTC().Format("20060102T150405Z"))
}

// MarshalArchive encodes logs + sessions + audit logs as gzipped NDJSON.
func MarshalArchive(logs []*store.LogEntry, sessions []*store.Session, auditLogs []*store.AuditLog) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := json.NewEncoder(gz)

	for _, l := range logs {
		raw, err := json.Marshal(l)
		if err != nil {
			return nil, err
		}
		if err := enc.Encode(ArchiveRecord{Type: "log", Payload: raw}); err != nil {
			return nil, err
		}
	}
	for _, s := range sessions {
		raw, err := json.Marshal(s)
		if err != nil {
			return nil, err
		}
		if err := enc.Encode(ArchiveRecord{Type: "session", Payload: raw}); err != nil {
			return nil, err
		}
	}
	for _, a := range auditLogs {
		raw, err := json.Marshal(a)
		if err != nil {
			return nil, err
		}
		if err := enc.Encode(ArchiveRecord{Type: "audit_log", Payload: raw}); err != nil {
			return nil, err
		}
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalArchive decompresses and parses an archive into logs + sessions + audit logs.
func UnmarshalArchive(data []byte) ([]*store.LogEntry, []*store.Session, []*store.AuditLog, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decompress: %w", err)
	}
	defer gz.Close()

	var logs []*store.LogEntry
	var sessions []*store.Session
	var auditLogs []*store.AuditLog

	dec := json.NewDecoder(gz)
	for dec.More() {
		var rec ArchiveRecord
		if err := dec.Decode(&rec); err != nil {
			continue
		}
		switch rec.Type {
		case "log":
			var l store.LogEntry
			if json.Unmarshal(rec.Payload, &l) == nil {
				logs = append(logs, &l)
			}
		case "session":
			var s store.Session
			if json.Unmarshal(rec.Payload, &s) == nil {
				sessions = append(sessions, &s)
			}
		case "audit_log":
			var a store.AuditLog
			if json.Unmarshal(rec.Payload, &a) == nil {
				auditLogs = append(auditLogs, &a)
			}
		}
	}
	return logs, sessions, auditLogs, nil
}

// ── Archiver interface ────────────────────────────────────────────────────────

type Archiver interface {
	Upload(ctx context.Context, key string, data []byte) error
	Download(ctx context.Context, key string) ([]byte, error)
	TestConnection(ctx context.Context) error
}

// ── S3 Archiver ───────────────────────────────────────────────────────────────

type s3Archiver struct{ client *s3client.Client }

func newS3Archiver(creds *S3Creds) (*s3Archiver, error) {
	c, err := s3client.NewClient(creds.Endpoint, creds.Protocol, creds.AccessKey, creds.SecretKey, creds.Region, creds.Bucket)
	if err != nil {
		return nil, fmt.Errorf("s3: %w", err)
	}
	return &s3Archiver{client: c}, nil
}

func (a *s3Archiver) Upload(ctx context.Context, key string, data []byte) error {
	return a.client.Upload(ctx, key, data, "application/gzip")
}
func (a *s3Archiver) Download(ctx context.Context, key string) ([]byte, error) {
	return a.client.Download(ctx, key)
}
func (a *s3Archiver) TestConnection(ctx context.Context) error {
	return a.client.TestConnection(ctx)
}

// ── NFS / Local Path Archiver ─────────────────────────────────────────────────

type nfsArchiver struct{ creds *NFSCreds }

func newNFSArchiver(creds *NFSCreds) *nfsArchiver { return &nfsArchiver{creds: creds} }

func (a *nfsArchiver) fullPath(key string) string {
	return filepath.Join(a.creds.MountPath, key)
}
func (a *nfsArchiver) Upload(_ context.Context, key string, data []byte) error {
	p := a.fullPath(key)
	// Deliberately not tightened to gosec's preferred 0750/0600: this is a shared
	// NFS archive by design (admin-configured MountPath) — other authorized
	// systems/tools are expected to read these files directly off the mount, and
	// owner-only permissions would silently break that.
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { // #nosec G301
		return fmt.Errorf("nfs mkdir: %w", err)
	}
	return os.WriteFile(p, data, 0o644) // #nosec G306
}
func (a *nfsArchiver) Download(_ context.Context, key string) ([]byte, error) {
	return os.ReadFile(a.fullPath(key))
}
func (a *nfsArchiver) TestConnection(_ context.Context) error {
	info, err := os.Stat(a.creds.MountPath)
	if err != nil {
		return fmt.Errorf("nfs path not accessible: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("nfs path is not a directory")
	}
	return nil
}

// ── Stub for backends not yet implemented ─────────────────────────────────────

type stubArchiver struct{ name string }

func (s *stubArchiver) Upload(_ context.Context, _ string, _ []byte) error {
	return fmt.Errorf("%s: not yet implemented", s.name)
}
func (s *stubArchiver) Download(_ context.Context, _ string) ([]byte, error) {
	return nil, fmt.Errorf("%s: not yet implemented", s.name)
}
func (s *stubArchiver) TestConnection(_ context.Context) error {
	return fmt.Errorf("%s: not yet implemented", s.name)
}

// ── Factory ───────────────────────────────────────────────────────────────────

// NewArchiver builds an Archiver for the given storage type and encrypted credentials blob.
func NewArchiver(storageType string, encCreds []byte) (Archiver, error) {
	switch storageType {
	case "s3":
		var c S3Creds
		if err := DecryptCreds(encCreds, &c); err != nil {
			return nil, fmt.Errorf("decrypt s3 creds: %w", err)
		}
		return newS3Archiver(&c)
	case "nfs":
		var c NFSCreds
		if err := DecryptCreds(encCreds, &c); err != nil {
			return nil, fmt.Errorf("decrypt nfs creds: %w", err)
		}
		return newNFSArchiver(&c), nil
	case "gcs":
		return &stubArchiver{name: "GCS"}, nil
	case "azure":
		return &stubArchiver{name: "Azure Blob Storage"}, nil
	case "sftp":
		return &stubArchiver{name: "SFTP"}, nil
	case "elasticsearch":
		return &stubArchiver{name: "Elasticsearch"}, nil
	case "siem":
		return &stubArchiver{name: "SIEM"}, nil
	default:
		return nil, fmt.Errorf("unknown storage type: %q", storageType)
	}
}
