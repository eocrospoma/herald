package actions

import (
	"bytes"
	"errors"
	"strings"

	"github.com/eocrospoma/herald/audit"
)

// errFake is a stand-in for a real command failure (nft/systemctl exiting
// non-zero), used by tests that exercise each action's error path.
var errFake = errors.New("fake command failure")

// fakeRunner records every call it receives instead of executing anything,
// and returns a canned (out, err) pair - lets tests exercise the
// success/failure paths of each action without a real nft/systemctl/sudo.
type fakeRunner struct {
	calls [][]string
	out   []byte
	err   error
}

func (f *fakeRunner) Run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return f.out, f.err
}

func (f *fakeRunner) lastCall() string {
	if len(f.calls) == 0 {
		return ""
	}
	return strings.Join(f.calls[len(f.calls)-1], " ")
}

func newTestActions(runner Runner) (*Actions, *bytes.Buffer) {
	var buf bytes.Buffer
	log := audit.NewLogger(&buf)
	return &Actions{Runner: runner, Log: log, AuditLogPath: "/nonexistent"}, &buf
}
