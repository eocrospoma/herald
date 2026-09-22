package main

import (
	"fmt"
	"os"
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

	return Config{
		ListenAddr:   addr,
		TOTPSecret:   []byte(secret),
		AuditLogPath: logPath,
	}, nil
}
