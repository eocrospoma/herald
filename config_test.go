package main

import "testing"

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
	if string(cfg.TOTPSecret) != "supersecret" {
		t.Errorf("TOTPSecret = %q, want %q", cfg.TOTPSecret, "supersecret")
	}
}

func TestLoadConfig_RespectsOverrides(t *testing.T) {
	t.Setenv("HERALD_TOTP_SECRET", "supersecret")
	t.Setenv("HERALD_LISTEN_ADDR", "0.0.0.0:9000")
	t.Setenv("HERALD_AUDIT_LOG_PATH", "/tmp/audit.jsonl")

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
}
