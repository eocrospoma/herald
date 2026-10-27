package actions

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoadWhitelistFile_RoundTripsUnchanged(t *testing.T) {
	path := writeTempWhitelistConf(t, []string{
		"allow 203.0.113.5; # herald-wl expires=2026-10-27T15:04:05Z",
	})
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading temp file: %v", err)
	}

	wf, err := loadWhitelistFile(path)
	if err != nil {
		t.Fatalf("loadWhitelistFile: %v", err)
	}

	rendered := wf.render()
	if rendered != string(original) {
		t.Errorf("render() did not round-trip:\n--- got ---\n%s\n--- want ---\n%s", rendered, original)
	}
	if len(wf.entries) != 1 || wf.entries[0].IP != "203.0.113.5" {
		t.Errorf("entries = %+v, want one entry for 203.0.113.5", wf.entries)
	}
}

func TestLoadWhitelistFile_MissingMarkersIsAnError(t *testing.T) {
	path := t.TempDir() + "/whitelist.conf"
	if err := os.WriteFile(path, []byte("allow 1.2.3.4;\ndeny all;\n"), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	if _, err := loadWhitelistFile(path); err == nil {
		t.Fatal("loadWhitelistFile succeeded on a file with no herald-managed markers, want error")
	}
}

func TestLoadWhitelistFile_UnrecognizedLineInManagedBlockIsAnError(t *testing.T) {
	path := writeTempWhitelistConf(t, []string{"allow 1.2.3.4;"}) // missing the "# herald-wl expires=..." suffix

	if _, err := loadWhitelistFile(path); err == nil {
		t.Fatal("loadWhitelistFile succeeded on an unrecognized managed-block line, want error")
	}
}

func TestWhitelistFile_UpsertAddsNewEntry(t *testing.T) {
	wf := &whitelistFile{}
	now := time.Now()

	wf.upsert("203.0.113.5", now.Add(15*time.Minute), now)

	if len(wf.entries) != 1 || wf.entries[0].IP != "203.0.113.5" {
		t.Fatalf("entries = %+v, want one entry for 203.0.113.5", wf.entries)
	}
}

func TestWhitelistFile_UpsertRefreshesExistingEntry(t *testing.T) {
	now := time.Now()
	wf := &whitelistFile{entries: []whitelistEntry{{IP: "203.0.113.5", Expires: now.Add(time.Minute)}}}

	newExpiry := now.Add(time.Hour)
	wf.upsert("203.0.113.5", newExpiry, now)

	if len(wf.entries) != 1 {
		t.Fatalf("entries = %+v, want exactly one (refreshed, not duplicated)", wf.entries)
	}
	if !wf.entries[0].Expires.Equal(newExpiry) {
		t.Errorf("Expires = %v, want %v", wf.entries[0].Expires, newExpiry)
	}
}

func TestWhitelistFile_UpsertPrunesExpiredEntries(t *testing.T) {
	now := time.Now()
	wf := &whitelistFile{entries: []whitelistEntry{
		{IP: "203.0.113.6", Expires: now.Add(-time.Minute)}, // already expired
	}}

	wf.upsert("203.0.113.5", now.Add(time.Hour), now)

	if len(wf.entries) != 1 || wf.entries[0].IP != "203.0.113.5" {
		t.Errorf("entries = %+v, want only the new entry (expired one pruned)", wf.entries)
	}
}

func TestWhitelistFile_Clear(t *testing.T) {
	wf := &whitelistFile{entries: []whitelistEntry{{IP: "203.0.113.5", Expires: time.Now().Add(time.Hour)}}}
	wf.clear()
	if len(wf.entries) != 0 {
		t.Errorf("entries = %+v, want none after clear", wf.entries)
	}
}

func TestApplyWhitelistChange_NoOpWhenNothingChanges(t *testing.T) {
	runner := &fakeRunner{}
	path := writeTempWhitelistConf(t, nil)
	a := &Actions{Runner: runner, WhitelistPath: path}

	err := a.applyWhitelistChange(func(wf *whitelistFile) { /* no-op mutation */ })
	if err != nil {
		t.Fatalf("applyWhitelistChange returned error: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Errorf("nginx was invoked despite no actual change: %v", runner.calls)
	}
}

func TestApplyWhitelistChange_RollsBackOnNginxTestFailure(t *testing.T) {
	runner := &fakeRunner{responses: []cmdResult{{out: []byte("syntax error"), err: errFake}}}
	path := writeTempWhitelistConf(t, nil)
	a := &Actions{Runner: runner, WhitelistPath: path}

	err := a.applyWhitelistChange(func(wf *whitelistFile) {
		wf.upsert("203.0.113.5", time.Now().Add(time.Hour), time.Now())
	})
	if err == nil {
		t.Fatal("applyWhitelistChange succeeded despite nginx -t failing, want error")
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("reading whitelist.conf after rollback: %v", readErr)
	}
	if strings.Contains(string(data), "203.0.113.5") {
		t.Errorf("whitelist.conf was not rolled back after nginx -t failed:\n%s", data)
	}

	cmds := runner.commands()
	if len(cmds) != 1 || !strings.Contains(cmds[0], "nginx -t") {
		t.Errorf("commands = %v, want only [nginx -t] (no reload attempted after a failed test)", cmds)
	}
}

func TestSweepExpiredWhitelist_RemovesOnlyExpired(t *testing.T) {
	now := time.Now()
	path := writeTempWhitelistConf(t, []string{
		"allow 203.0.113.5; # herald-wl expires=" + now.Add(-time.Minute).UTC().Format(time.RFC3339),
		"allow 203.0.113.6; # herald-wl expires=" + now.Add(time.Hour).UTC().Format(time.RFC3339),
	})
	runner := &fakeRunner{}
	a := &Actions{Runner: runner, WhitelistPath: path}

	if err := a.SweepExpiredWhitelist(); err != nil {
		t.Fatalf("SweepExpiredWhitelist: %v", err)
	}

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "203.0.113.5") {
		t.Errorf("expired entry 203.0.113.5 was not removed:\n%s", data)
	}
	if !strings.Contains(string(data), "203.0.113.6") {
		t.Errorf("non-expired entry 203.0.113.6 was incorrectly removed:\n%s", data)
	}
	if len(runner.calls) != 2 {
		t.Errorf("calls = %v, want nginx -t + reload since something was actually pruned", runner.calls)
	}
}

func TestSweepExpiredWhitelist_NoOpWhenNothingExpired(t *testing.T) {
	path := writeTempWhitelistConf(t, []string{
		"allow 203.0.113.6; # herald-wl expires=" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	runner := &fakeRunner{}
	a := &Actions{Runner: runner, WhitelistPath: path}

	if err := a.SweepExpiredWhitelist(); err != nil {
		t.Fatalf("SweepExpiredWhitelist: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Errorf("nginx was invoked despite nothing expired: %v", runner.calls)
	}
}
