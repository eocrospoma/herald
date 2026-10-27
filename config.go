package main

import (
	"fmt"
	"os"
	"time"
)

// Config holds Herald's runtime configuration, populated from environment
// variables. See .env.example for the full list.
type Config struct {
	// ListenAddr is the address Herald's HTTP server binds to. Herald sits
	// behind host-nginx, which reverse-proxies to it - never exposed
	// directly to the internet, so this defaults to loopback-only.
	ListenAddr string

	// TOTPSecret is the raw shared secret bytes for HOTP/TOTP. Required -
	// Herald refuses to start without it rather than run with an empty
	// secret, since that would leave the "gate" wide open.
	TOTPSecret []byte

	// AuditLogPath is where the JSON-Lines audit log is appended.
	AuditLogPath string

	// WhitelistPath is nginx's whitelist.conf, which must already have
	// Herald's managed-block markers (see actions/nginx_whitelist.go).
	WhitelistPath string

	// WhitelistTTL is how long a whitelisted IP stays allowed before the
	// background sweeper (see main.go) removes it.
	WhitelistTTL time.Duration
}

// LoadConfig reads configuration from the environment. It returns an error
// for anything required but missing, rather than defaulting or panicking -
// a misconfigured Herald is a security gate silently left open.
func LoadConfig() (Config, error) {
	secret := os.Getenv("HERALD_TOTP_SECRET")
	if secret == "" {
		return Config{}, fmt.Errorf("HERALD_TOTP_SECRET is not set")
	}

	addr := os.Getenv("HERALD_LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8420"
	}

	logPath := os.Getenv("HERALD_AUDIT_LOG_PATH")
	if logPath == "" {
		logPath = "/var/log/herald/audit.jsonl"
	}

	whitelistPath := os.Getenv("HERALD_WHITELIST_PATH")
	if whitelistPath == "" {
		whitelistPath = "/etc/nginx/sites-available/whitelist.conf"
	}

	ttl := 15 * time.Minute
	if raw := os.Getenv("HERALD_WHITELIST_TTL"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("HERALD_WHITELIST_TTL %q: %w", raw, err)
		}
		ttl = parsed
	}

	return Config{
		ListenAddr:    addr,
		TOTPSecret:    []byte(secret),
		AuditLogPath:  logPath,
		WhitelistPath: whitelistPath,
		WhitelistTTL:  ttl,
	}, nil
}
