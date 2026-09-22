package actions

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWhitelist_Success(t *testing.T) {
	runner := &fakeRunner{out: []byte("ok")}
	a, _ := newTestActions(runner)

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

	call := runner.lastCall()
	if !strings.Contains(call, "nft add element inet filter allowed_ips") {
		t.Errorf("nft call = %q, missing expected command", call)
	}
	if !strings.Contains(call, "203.0.113.5") || !strings.Contains(call, "timeout 900s") {
		t.Errorf("nft call = %q, missing IP or timeout", call)
	}
}

func TestWhitelist_RejectsUnparseableSourceIP(t *testing.T) {
	runner := &fakeRunner{}
	a, buf := newTestActions(runner)

	req := httptest.NewRequest(http.MethodGet, "/herald/wl", nil)
	req.RemoteAddr = "not-an-ip:54321"
	rr := httptest.NewRecorder()

	a.Whitelist(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if len(runner.calls) != 0 {
		t.Errorf("nft was invoked despite an unparseable source IP: %v", runner.calls)
	}
	if !strings.Contains(buf.String(), `"error"`) {
		t.Errorf("audit log missing error entry: %q", buf.String())
	}
}

func TestWhitelist_CommandFailureReturns500AndLogsError(t *testing.T) {
	runner := &fakeRunner{out: []byte("nft: permission denied"), err: errFake}
	a, buf := newTestActions(runner)

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
}
