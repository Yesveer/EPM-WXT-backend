package api

import (
	"strings"
	"testing"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

func TestRecordingKeyLayout(t *testing.T) {
	m := &store.Machine{
		OrgID:    "acme",
		TenantID: "acme-tenant",
		GroupIDs: []string{"support-team", "second-group"},
		Name:     "kaal-laptop",
		AgentID:  "agent-1",
	}

	got := recordingKey(m, "priya", "rc_abc123")
	want := "acme/support-team/kaal-laptop/priya/rc_abc123/desktop.guac"
	if got != want {
		t.Errorf("key = %q, want %q", got, want)
	}
}

// A machine name is user-chosen and can contain anything. A slash in one would
// silently write the recording into a different folder than the one the portal
// later looks in, so every segment has to be flattened.
func TestRecordingKeyNeverGainsExtraSegments(t *testing.T) {
	m := &store.Machine{
		OrgID:    "acme/../evil",
		GroupIDs: []string{"a/b"},
		Name:     "Kaal's Laptop / spare",
		AgentID:  "agent-1",
	}

	got := recordingKey(m, "user name", "sess/1")
	if n := strings.Count(got, "/"); n != 5 {
		t.Errorf("key %q has %d separators, want exactly 5", got, n)
	}
	if strings.Contains(got, "..") {
		t.Errorf("key %q still contains a traversal sequence", got)
	}
}

func TestRecordingKeyFallsBackForMissingValues(t *testing.T) {
	t.Run("no organisation falls back to the tenant", func(t *testing.T) {
		m := &store.Machine{TenantID: "tenant-9", Name: "box", AgentID: "a1"}
		got := recordingKey(m, "u", "s")
		if !strings.HasPrefix(got, "tenant-9/") {
			t.Errorf("key = %q, want it to start with the tenant", got)
		}
	})

	t.Run("no group becomes ungrouped", func(t *testing.T) {
		m := &store.Machine{OrgID: "acme", Name: "box", AgentID: "a1"}
		got := recordingKey(m, "u", "s")
		if !strings.HasPrefix(got, "acme/ungrouped/") {
			t.Errorf("key = %q, want an ungrouped segment", got)
		}
	})

	t.Run("no machine name falls back to the agent id", func(t *testing.T) {
		m := &store.Machine{OrgID: "acme", GroupIDs: []string{"g"}, AgentID: "agent-7"}
		got := recordingKey(m, "u", "s")
		if !strings.Contains(got, "/agent-7/") {
			t.Errorf("key = %q, want the agent id as the machine segment", got)
		}
	})

	t.Run("an empty segment never collapses the path", func(t *testing.T) {
		m := &store.Machine{}
		got := recordingKey(m, "", "")
		if strings.Contains(got, "//") {
			t.Errorf("key %q collapsed to an empty segment", got)
		}
		if n := strings.Count(got, "/"); n != 5 {
			t.Errorf("key %q has %d separators, want exactly 5", got, n)
		}
	})
}

func TestKeySegmentSanitising(t *testing.T) {
	tests := map[string]string{
		"simple":         "simple",
		"With Spaces":    "With-Spaces",
		"a/b":            "a-b",
		"dots.are.fine":  "dots.are.fine",
		"under_score-ok": "under_score-ok",
		"emoji✓here":     "emoji-here",
		"--trimmed--":    "trimmed",
		"  padded  ":     "padded",
	}
	for in, want := range tests {
		if got := keySegment(in, "fallback"); got != want {
			t.Errorf("keySegment(%q) = %q, want %q", in, got, want)
		}
	}

	for _, in := range []string{"", "   ", "///", "---"} {
		if got := keySegment(in, "fallback"); got != "fallback" {
			t.Errorf("keySegment(%q) = %q, want the fallback", in, got)
		}
	}
}
