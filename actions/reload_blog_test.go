package actions

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReloadBlog_Success(t *testing.T) {
	runner := &fakeRunner{}
	a, _ := newTestActions(runner)

	req := httptest.NewRequest(http.MethodGet, "/herald/reload-blog", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	rr := httptest.NewRecorder()

	a.ReloadBlog(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if runner.lastCall() != "sudo systemctl restart blog" {
		t.Errorf("call = %q, want the hardcoded restart command", runner.lastCall())
	}
}

func TestReloadBlog_CommandFailureReturns500AndLogsError(t *testing.T) {
	runner := &fakeRunner{responses: []cmdResult{{out: []byte("unit not found"), err: errFake}}}
	a, buf := newTestActions(runner)

	req := httptest.NewRequest(http.MethodGet, "/herald/reload-blog", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	rr := httptest.NewRecorder()

	a.ReloadBlog(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
	if !strings.Contains(buf.String(), `"reload-blog"`) || !strings.Contains(buf.String(), `"error"`) {
		t.Errorf("audit log missing reload-blog/error entry: %q", buf.String())
	}
}
