package main

import (
	"testing"
	"time"
)

func TestLoadConfig_RequiresTOTPSecret(t *testing.T) {
	t.Setenv("HERALD_TOTP_SECRET", "")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("LoadConfig succeeded with no HERALD_TOTP_SECRET, want error")
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	t.Setenv("HERALD_TOTP_SECRET", "supersecret")
	t.Setenv("HERALD_LISTEN_ADDR", "")
	t.Setenv("HERALD_AUDIT_LOG_PATH", "")
	t.Setenv("HERALD_WHITELIST_PATH", "")
	t.Setenv("HERALD_WHITELIST_TTL", "")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:8420" {
		t.Errorf("ListenAddr = %q, want default 127.0.0.1:8420", cfg.ListenAddr)
	}
	if cfg.AuditLogPath != "/var/log/herald/audit.jsonl" {
		t.Errorf("AuditLogPath = %q, want default", cfg.AuditLogPath)
	}
	if cfg.WhitelistPath != "/etc/nginx/sites-available/whitelist.conf" {
		t.Errorf("WhitelistPath = %q, want default", cfg.WhitelistPath)
	}
	if cfg.WhitelistTTL != 15*time.Minute {
		t.Errorf("WhitelistTTL = %v, want 15m default", cfg.WhitelistTTL)
	}
	if string(cfg.TOTPSecret) != "supersecret" {
		t.Errorf("TOTPSecret = %q, want %q", cfg.TOTPSecret, "supersecret")
	}
}

func TestLoadConfig_RespectsOverrides(t *testing.T) {
	t.Setenv("HERALD_TOTP_SECRET", "supersecret")
	t.Setenv("HERALD_LISTEN_ADDR", "0.0.0.0:9000")
	t.Setenv("HERALD_AUDIT_LOG_PATH", "/tmp/audit.jsonl")
	t.Setenv("HERALD_WHITELIST_PATH", "/tmp/whitelist.conf")
	t.Setenv("HERALD_WHITELIST_TTL", "5m")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	if cfg.ListenAddr != "0.0.0.0:9000" {
		t.Errorf("ListenAddr = %q, want override", cfg.ListenAddr)
	}
	if cfg.AuditLogPath != "/tmp/audit.jsonl" {
		t.Errorf("AuditLogPath = %q, want override", cfg.AuditLogPath)
	}
	if cfg.WhitelistPath != "/tmp/whitelist.conf" {
		t.Errorf("WhitelistPath = %q, want override", cfg.WhitelistPath)
	}
	if cfg.WhitelistTTL != 5*time.Minute {
		t.Errorf("WhitelistTTL = %v, want 5m override", cfg.WhitelistTTL)
	}
}

func TestLoadConfig_RejectsInvalidTTL(t *testing.T) {
	t.Setenv("HERALD_TOTP_SECRET", "supersecret")
	t.Setenv("HERALD_WHITELIST_TTL", "not-a-duration")

	if _, err := LoadConfig(); err == nil {
		t.Fatal("LoadConfig succeeded with an invalid HERALD_WHITELIST_TTL, want error")
	}
}
