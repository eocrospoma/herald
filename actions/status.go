package actions

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"time"
)

type whitelistStatusEntry struct {
	IP        string `json:"ip"`
	ExpiresIn string `json:"expires_in"`
}

// statusResponse mixes Herald's current managed whitelist entries with the
// tail of the audit log. RecentAudit uses json.RawMessage so each
// already-JSON audit line passes through unmodified instead of being
// re-encoded as a string.
type statusResponse struct {
	Whitelist      []whitelistStatusEntry `json:"whitelist,omitempty"`
	WhitelistError string                 `json:"whitelist_error,omitempty"`
	RecentAudit    []json.RawMessage      `json:"recent_audit,omitempty"`
	AuditError     string                 `json:"audit_error,omitempty"`
}

// Status handles GET /herald/status: read-only, reports the current
// whitelist contents and recent audit activity.
func (a *Actions) Status(w http.ResponseWriter, r *http.Request) {
	var resp statusResponse

	wf, err := loadWhitelistFile(a.WhitelistPath)
	if err != nil {
		resp.WhitelistError = err.Error()
	} else {
		now := time.Now()
		for _, e := range wf.entries {
			if !e.Expires.After(now) {
				continue // already expired, just hasn't been swept yet
			}
			resp.Whitelist = append(resp.Whitelist, whitelistStatusEntry{
				IP:        e.IP,
				ExpiresIn: e.Expires.Sub(now).Round(time.Second).String(),
			})
		}
	}

	lines, err := tailLines(a.AuditLogPath, statusLogLines)
	if err != nil {
		resp.AuditError = err.Error()
	} else {
		for _, l := range lines {
			resp.RecentAudit = append(resp.RecentAudit, json.RawMessage(l))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// tailLines returns the last n lines of the file at path.
func tailLines(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}
