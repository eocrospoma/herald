// Package actions implements Herald's privileged operations. Every
// exported method here only ever runs after the caller's TOTP code has
// already been verified by the registry's middleware - these methods trust
// that and focus solely on doing the one thing their path name says.
package actions

import (
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/eocrospoma/herald/audit"
)

const statusLogLines = 20

// Runner executes an external command and returns its combined output.
// Abstracted so tests can substitute a fake instead of shelling out to the
// real nginx/systemctl/sudo, which don't exist outside the deploy target.
type Runner interface {
	Run(name string, args ...string) ([]byte, error)
}

// execRunner is the production Runner, backed by os/exec. It never goes
// through a shell - args are passed straight to exec.Command - so classic
// shell-injection via argument content isn't a concern; inputs are still
// validated where they come from the request (see whitelist.go).
type execRunner struct{}

func (execRunner) Run(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// Actions holds what the handlers need beyond the request itself.
type Actions struct {
	Runner       Runner
	Log          *audit.Logger
	AuditLogPath string

	// WhitelistPath is nginx's whitelist.conf - see nginx_whitelist.go for
	// the file format and why Herald owns only a delimited block of it.
	WhitelistPath string
	WhitelistTTL  time.Duration

	// whitelistMu serializes every read-modify-write of WhitelistPath
	// (Whitelist, RevokeAll, and the background expiry sweeper all go
	// through it), since the file itself has no locking of its own.
	whitelistMu sync.Mutex
}

// New builds production Actions, backed by the real exec.Command runner.
func New(log *audit.Logger, auditLogPath, whitelistPath string, whitelistTTL time.Duration) *Actions {
	return &Actions{
		Runner:        execRunner{},
		Log:           log,
		AuditLogPath:  auditLogPath,
		WhitelistPath: whitelistPath,
		WhitelistTTL:  whitelistTTL,
	}
}

func (a *Actions) logError(action, ip string, err error) {
	_ = a.Log.Log(audit.Entry{Action: action, SourceIP: ip, Result: "error", Detail: err.Error()})
}

func cmdError(err error, out []byte) error {
	return fmt.Errorf("%w: %s", err, out)
}
