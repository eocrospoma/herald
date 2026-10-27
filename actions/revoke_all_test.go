package actions

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRevokeAll_Success(t *testing.T) {
	runner := &fakeRunner{}
	path := writeTempWhitelistConf(t, []string{
		"allow 203.0.113.5; # herald-wl expires=" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"allow 203.0.113.6; # herald-wl expires=" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	a, _ := newTestActions(runner)
	a.WhitelistPath = path

	req := httptest.NewRequest(http.MethodPost, "/herald/revoke-all", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	rr := httptest.NewRecorder()

	a.RevokeAll(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "herald-wl") {
		t.Errorf("whitelist.conf still has managed entries after revoke-all:\n%s", data)
	}
	if !strings.Contains(string(data), "allow 192.168.254.0/24;") {
		t.Errorf("static entry was lost from whitelist.conf:\n%s", data)
	}

	cmds := runner.commands()
	if len(cmds) != 2 || !strings.Contains(cmds[0], "nginx -t") || !strings.Contains(cmds[1], "systemctl reload nginx") {
		t.Errorf("commands = %v, want [nginx -t, systemctl reload nginx]", cmds)
	}
}

func TestRevokeAll_NoOpWhenAlreadyEmpty(t *testing.T) {
	runner := &fakeRunner{}
	path := writeTempWhitelistConf(t, nil)
	a, _ := newTestActions(runner)
	a.WhitelistPath = path

	req := httptest.NewRequest(http.MethodPost, "/herald/revoke-all", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	rr := httptest.NewRecorder()

	a.RevokeAll(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if len(runner.calls) != 0 {
		t.Errorf("nginx was invoked despite nothing to revoke: %v", runner.calls)
	}
}

func TestRevokeAll_NginxTestFailureReturns500(t *testing.T) {
	runner := &fakeRunner{responses: []cmdResult{{err: errFake}}}
	path := writeTempWhitelistConf(t, []string{
		"allow 203.0.113.5; # herald-wl expires=" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	a, buf := newTestActions(runner)
	a.WhitelistPath = path

	req := httptest.NewRequest(http.MethodPost, "/herald/revoke-all", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	rr := httptest.NewRecorder()

	a.RevokeAll(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
	if !strings.Contains(buf.String(), `"revoke-all"`) || !strings.Contains(buf.String(), `"error"`) {
		t.Errorf("audit log missing revoke-all/error entry: %q", buf.String())
	}
}
