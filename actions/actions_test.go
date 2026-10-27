package actions

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eocrospoma/herald/audit"
)

// errFake is a stand-in for a real command failure (nginx/systemctl exiting
// non-zero), used by tests that exercise each action's error path.
var errFake = errors.New("fake command failure")

type cmdResult struct {
	out []byte
	err error
}

// fakeRunner records every call it receives instead of executing anything.
// Each call consumes the next entry in responses, in order; once responses
// is exhausted, further calls succeed with no output - this lets a test
// fail just one call in a multi-command sequence (e.g. "nginx -t" passes
// but "systemctl reload nginx" fails) without having to script every call.
type fakeRunner struct {
	calls     [][]string
	responses []cmdResult
}

func (f *fakeRunner) Run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	idx := len(f.calls) - 1
	if idx < len(f.responses) {
		r := f.responses[idx]
		return r.out, r.err
	}
	return nil, nil
}

func (f *fakeRunner) lastCall() string {
	if len(f.calls) == 0 {
		return ""
	}
	return strings.Join(f.calls[len(f.calls)-1], " ")
}

func (f *fakeRunner) commands() []string {
	cmds := make([]string, len(f.calls))
	for i, c := range f.calls {
		cmds[i] = strings.Join(c, " ")
	}
	return cmds
}

// writeTempWhitelistConf builds a whitelist.conf like the real one on the
// VPS: some hand-maintained static entries, Herald's managed block
// (seeded with managedLines), and the trailing deny-all.
func writeTempWhitelistConf(t *testing.T, managedLines []string) string {
	t.Helper()

	var lines []string
	lines = append(lines,
		"allow 192.168.254.0/24;",
		"allow 38.25.15.118; # erick mac, added 2026-09-06 for argocd",
		managedBeginMarker,
	)
	lines = append(lines, managedLines...)
	lines = append(lines, managedEndMarker, "deny all;")

	path := filepath.Join(t.TempDir(), "whitelist.conf")
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp whitelist.conf: %v", err)
	}
	return path
}

func newTestActions(runner Runner) (*Actions, *bytes.Buffer) {
	var buf bytes.Buffer
	log := audit.NewLogger(&buf)
	return &Actions{
		Runner:       runner,
		Log:          log,
		AuditLogPath: "/nonexistent",
		WhitelistTTL: 15 * time.Minute,
	}, &buf
}
