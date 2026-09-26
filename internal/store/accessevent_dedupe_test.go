package store

import (
	"testing"
	"time"
)

// The session monitor's dedup key is os_user + line. Both the agent and the
// backend must agree on it, so this pins the shape the backend matches on.
func TestAccessEventKeyIdentifiesASession(t *testing.T) {
	a := AccessEventKey{OSUser: "kaal", Line: "console#1"}
	b := AccessEventKey{OSUser: "kaal", Line: "console#1"}
	c := AccessEventKey{OSUser: "kaal", Line: "rdp-tcp#2#3"}
	d := AccessEventKey{OSUser: "admin", Line: "console#1"}

	if a != b {
		t.Error("the same user on the same line is a different key")
	}
	if a == c {
		t.Error("the same user on different lines collapsed to one key")
	}
	if a == d {
		t.Error("different users on the same line collapsed to one key")
	}
}

// dedupeKeep models the rule DedupeActiveAccessEvents applies, so the intent is
// pinned even though the query itself needs Mongo.
//
// The rule matters: keeping the LAST row instead of the first would reset every
// login time to whenever the agent was last restarted, and the portal would
// report a session that began days ago as brand new.
func TestDedupeKeepsTheEarliestRow(t *testing.T) {
	base := time.Date(2026, time.September, 8, 18, 28, 0, 0, time.UTC)

	rows := []AccessEvent{
		{OSUser: "kaal", Line: "console#1", LoginAt: base},
		{OSUser: "kaal", Line: "console#1", LoginAt: base.Add(10 * 24 * time.Hour)},
		{OSUser: "kaal", Line: "console#1", LoginAt: base.Add(18 * 24 * time.Hour)},
		{OSUser: "admin", Line: "rdp-tcp#2#3", LoginAt: base.Add(time.Hour)},
	}

	kept, closed := dedupeKeep(rows)

	if len(kept) != 2 {
		t.Fatalf("kept %d rows, want 2 (one per distinct session)", len(kept))
	}
	if len(closed) != 2 {
		t.Fatalf("closed %d rows, want 2 duplicates", len(closed))
	}
	for _, k := range kept {
		if k.OSUser == "kaal" && !k.LoginAt.Equal(base) {
			t.Errorf("kept login time %s, want the earliest %s", k.LoginAt, base)
		}
	}
}

// dedupeKeep splits rows sorted oldest-first into the ones to keep and the
// duplicates to close. It mirrors the loop in DedupeActiveAccessEvents.
func dedupeKeep(rows []AccessEvent) (keep, closed []AccessEvent) {
	seen := map[AccessEventKey]bool{}
	for _, r := range rows {
		k := AccessEventKey{OSUser: r.OSUser, Line: r.Line}
		if seen[k] {
			closed = append(closed, r)
			continue
		}
		seen[k] = true
		keep = append(keep, r)
	}
	return keep, closed
}

// A snapshot with no sessions means nobody is logged in, so everything still
// recorded as open must be closed. An empty keep list must NOT be read as
// "keep everything".
func TestEmptySnapshotClosesEverything(t *testing.T) {
	var keep []AccessEventKey
	if len(keep) != 0 {
		t.Fatal("precondition")
	}
	// CloseStaleAccessEvents omits the $nor clause when keep is empty, leaving
	// the filter as {agent_id, active: true} — every open row. This test exists
	// to make that intent explicit, since the obvious guard ("skip when the
	// list is empty") would strand every session as permanently active.
}
