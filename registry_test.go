package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eocrospoma/herald/audit"
)

func testRegistry(t *testing.T, actionCalled *bool) (registry, *TOTPVerifier, *audit.Logger, *bytes.Buffer) {
	t.Helper()
	secret := []byte("12345678901234567890")
	verifier := NewTOTPVerifier(secret)
	var buf bytes.Buffer
	log := audit.NewLogger(&buf)

	reg := registry{
		"/herald/status": route{
			method: http.MethodGet,
			name:   "status",
			action: func(w http.ResponseWriter, r *http.Request) {
				*actionCalled = true
				w.WriteHeader(http.StatusOK)
			},
		},
	}
	return reg, verifier, log, &buf
}

func TestServe_UnknownPathReturns404WithNoSideEffects(t *testing.T) {
	called := false
	reg, verifier, log, buf := testRegistry(t, &called)

	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	rr := httptest.NewRecorder()
	reg.handler(verifier, log).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
	if called {
		t.Error("action was called for an unregistered path")
	}
	if buf.Len() != 0 {
		t.Errorf("audit log got a write for an unregistered path: %q", buf.String())
	}
}

func TestServe_WrongMethodReturns405(t *testing.T) {
	called := false
	reg, verifier, log, _ := testRegistry(t, &called)

	req := httptest.NewRequest(http.MethodPost, "/herald/status", nil)
	rr := httptest.NewRecorder()
	reg.handler(verifier, log).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
	if called {
		t.Error("action was called despite wrong method")
	}
}

func TestServe_InvalidCodeReturns401AndLogs(t *testing.T) {
	called := false
	reg, verifier, log, buf := testRegistry(t, &called)

	req := httptest.NewRequest(http.MethodGet, "/herald/status?code=000000", nil)
	rr := httptest.NewRecorder()
	reg.handler(verifier, log).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if called {
		t.Error("action was called despite invalid code")
	}
	if !strings.Contains(buf.String(), `"unauthorized"`) {
		t.Errorf("audit log missing unauthorized entry: %q", buf.String())
	}
}

func TestServe_ValidCodeDispatchesAction(t *testing.T) {
	called := false
	secret := []byte("12345678901234567890")
	reg := registry{
		"/herald/status": route{
			method: http.MethodGet,
			name:   "status",
			action: func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			},
		},
	}
	verifier := NewTOTPVerifier(secret)
	var buf bytes.Buffer
	log := audit.NewLogger(&buf)

	code := hotp(secret, uint64(totpStep(time.Now())))
	req := httptest.NewRequest(http.MethodGet, "/herald/status?code="+code, nil)
	rr := httptest.NewRecorder()
	reg.handler(verifier, log).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if !called {
		t.Error("action was not called despite a valid code")
	}
	if !strings.Contains(buf.String(), `"ok"`) {
		t.Errorf("audit log missing ok entry: %q", buf.String())
	}
}
