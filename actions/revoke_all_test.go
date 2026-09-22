package actions

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRevokeAll_Success(t *testing.T) {
	runner := &fakeRunner{out: []byte("ok")}
	a, _ := newTestActions(runner)

	req := httptest.NewRequest(http.MethodPost, "/herald/revoke-all", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	rr := httptest.NewRecorder()

	a.RevokeAll(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if runner.lastCall() != "sudo nft flush set inet filter allowed_ips" {
		t.Errorf("call = %q, want the flush command", runner.lastCall())
	}
}

func TestRevokeAll_CommandFailureReturns500AndLogsError(t *testing.T) {
	runner := &fakeRunner{out: []byte("nft: permission denied"), err: errFake}
	a, buf := newTestActions(runner)

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
