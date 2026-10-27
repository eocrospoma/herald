package actions

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestWhitelist_Success(t *testing.T) {
	runner := &fakeRunner{}
	path := writeTempWhitelistConf(t, nil)
	a, _ := newTestActions(runner)
	a.WhitelistPath = path

	req := httptest.NewRequest(http.MethodGet, "/herald/wl", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	rr := httptest.NewRecorder()

	a.Whitelist(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "203.0.113.5") {
		t.Errorf("body %q does not mention the whitelisted IP", rr.Body.String())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading whitelist.conf: %v", err)
	}
	if !strings.Contains(string(data), "allow 203.0.113.5; # herald-wl expires=") {
		t.Errorf("whitelist.conf does not contain the new entry:\n%s", data)
	}
	// Pre-existing hand-maintained entries must be untouched.
	if !strings.Contains(string(data), "allow 192.168.254.0/24;") {
		t.Errorf("static entry was lost from whitelist.conf:\n%s", data)
	}

	cmds := runner.commands()
	if len(cmds) != 2 || !strings.Contains(cmds[0], "nginx -t") || !strings.Contains(cmds[1], "systemctl reload nginx") {
		t.Errorf("commands = %v, want [nginx -t, systemctl reload nginx]", cmds)
	}
}

func TestWhitelist_RejectsUnparseableSourceIP(t *testing.T) {
	runner := &fakeRunner{}
	path := writeTempWhitelistConf(t, nil)
	a, buf := newTestActions(runner)
	a.WhitelistPath = path

	req := httptest.NewRequest(http.MethodGet, "/herald/wl", nil)
	req.RemoteAddr = "not-an-ip:54321"
	rr := httptest.NewRecorder()

	a.Whitelist(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if len(runner.calls) != 0 {
		t.Errorf("nginx was invoked despite an unparseable source IP: %v", runner.calls)
	}
	if !strings.Contains(buf.String(), `"error"`) {
		t.Errorf("audit log missing error entry: %q", buf.String())
	}
}

func TestWhitelist_NginxTestFailureReturns500AndLogsErrorWithoutWriting(t *testing.T) {
	runner := &fakeRunner{responses: []cmdResult{{out: []byte("syntax error"), err: errFake}}}
	path := writeTempWhitelistConf(t, nil)
	a, buf := newTestActions(runner)
	a.WhitelistPath = path

	req := httptest.NewRequest(http.MethodGet, "/herald/wl", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	rr := httptest.NewRecorder()

	a.Whitelist(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
	if !strings.Contains(buf.String(), `"wl"`) || !strings.Contains(buf.String(), `"error"`) {
		t.Errorf("audit log missing wl/error entry: %q", buf.String())
	}

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "203.0.113.5") {
		t.Error("whitelist.conf was left with the new entry despite nginx -t failing - should have been written but the caller never got confirmation it's live")
	}
}
