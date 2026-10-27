// Herald is a small HTTP service exposing a fixed, closed set of
// TOTP-gated verbs for managing access to this host from anywhere - most
// importantly, whitelisting the caller's own IP into the host firewall.
//
// It runs as a single binary directly on the host (deliberately not
// Kubernetes): it mutates the host firewall and host services, which in
// k8s would need a privileged/hostNetwork pod, and as the emergency-access
// tool it can't depend on the cluster it grants access to. It sits behind
// the existing host-nginx for TLS and a consistent access-log format.
//
// Security is TOTP-only, by design: every path is meant to be fully
// public (bookmarked on a phone, even listed on a CV) - fail2ban on
// repeated 401s is defense-in-depth, not the real gate.
package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/eocrospoma/herald/actions"
	"github.com/eocrospoma/herald/audit"
)

// sweepInterval is how often the background sweeper checks for expired
// whitelist entries - independent of WhitelistTTL, just how promptly an
// expiry is actually noticed and acted on.
const sweepInterval = time.Minute

func main() {
	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(cfg.AuditLogPath), 0o750); err != nil {
		log.Fatalf("audit log dir: %v", err)
	}
	logFile, err := os.OpenFile(cfg.AuditLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		log.Fatalf("opening audit log %s: %v", cfg.AuditLogPath, err)
	}
	defer logFile.Close()

	auditLog := audit.NewLogger(logFile)
	verifier := NewTOTPVerifier(cfg.TOTPSecret)
	act := actions.New(auditLog, cfg.AuditLogPath, cfg.WhitelistPath, cfg.WhitelistTTL)

	go func() {
		for range time.Tick(sweepInterval) {
			if err := act.SweepExpiredWhitelist(); err != nil {
				log.Printf("whitelist sweep: %v", err)
			}
		}
	}()

	reg := registry{
		"/herald/wl": {
			method: http.MethodGet,
			name:   "wl",
			action: act.Whitelist,
		},
		"/herald/reload-blog": {
			method: http.MethodGet,
			name:   "reload-blog",
			action: act.ReloadBlog,
		},
		"/herald/status": {
			method: http.MethodGet,
			name:   "status",
			action: act.Status,
		},
		"/herald/revoke-all": {
			method: http.MethodPost,
			name:   "revoke-all",
			action: act.RevokeAll,
		},
	}

	log.Printf("herald listening on %s", cfg.ListenAddr)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, reg.handler(verifier, auditLog)))
}
