package actions

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempAuditLog(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing temp audit log: %v", err)
	}
	return path
}

func TestStatus_CombinesWhitelistAndAuditTail(t *testing.T) {
	runner := &fakeRunner{out: []byte(`[{"nftables":[]}]`)}
	logPath := writeTempAuditLog(t, []string{
		`{"action":"wl","result":"ok"}`,
		`{"action":"status","result":"ok"}`,
	})
	a, _ := newTestActions(runner)
	a.AuditLogPath = logPath

	req := httptest.NewRequest(http.MethodGet, "/herald/status", nil)
	rr := httptest.NewRecorder()

	a.Status(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	var resp statusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, rr.Body.String())
	}
	if resp.WhitelistError != "" {
		t.Errorf("whitelist_error = %q, want empty", resp.WhitelistError)
	}
	if len(resp.RecentAudit) != 2 {
		t.Errorf("recent_audit has %d entries, want 2", len(resp.RecentAudit))
	}
}

func TestStatus_ReportsNftFailureWithoutFailingTheRequest(t *testing.T) {
	runner := &fakeRunner{out: []byte("permission denied"), err: errFake}
	logPath := writeTempAuditLog(t, []string{`{"action":"wl","result":"ok"}`})
	a, _ := newTestActions(runner)
	a.AuditLogPath = logPath

	req := httptest.NewRequest(http.MethodGet, "/herald/status", nil)
	rr := httptest.NewRecorder()

	a.Status(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (nft failure is reported in the body, not a 500)", rr.Code)
	}

	var resp statusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if resp.WhitelistError == "" {
		t.Error("whitelist_error is empty, want the nft failure reported")
	}
}

func TestTailLines_ReturnsOnlyLastN(t *testing.T) {
	var lines []string
	for i := 0; i < 30; i++ {
		lines = append(lines, fmt.Sprintf(`{"n":%d}`, i))
	}
	path := writeTempAuditLog(t, lines)

	got, err := tailLines(path, 5)
	if err != nil {
		t.Fatalf("tailLines returned error: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d lines, want 5", len(got))
	}
	if got[0] != `{"n":25}` || got[4] != `{"n":29}` {
		t.Errorf("got %v, want the last 5 entries (n=25..29)", got)
	}
}

func TestTailLines_MissingFileReturnsError(t *testing.T) {
	if _, err := tailLines("/nonexistent/path/audit.jsonl", 5); err == nil {
		t.Fatal("tailLines succeeded for a missing file, want error")
	}
}
