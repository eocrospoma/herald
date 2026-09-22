package actions

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
)

// statusResponse mixes the live nftables set (active IPs + remaining TTL)
// with the tail of the audit log. Fields use json.RawMessage so the
// underlying JSON (from nft -j, and from each already-JSON audit line)
// passes through unmodified instead of being re-encoded as a string.
type statusResponse struct {
	Whitelist      json.RawMessage   `json:"whitelist,omitempty"`
	WhitelistError string            `json:"whitelist_error,omitempty"`
	RecentAudit    []json.RawMessage `json:"recent_audit,omitempty"`
	AuditError     string            `json:"audit_error,omitempty"`
}

// Status handles GET /herald/status: read-only, reports the current
// whitelist contents and recent audit activity.
func (a *Actions) Status(w http.ResponseWriter, r *http.Request) {
	var resp statusResponse

	out, err := a.Runner.Run("sudo", "nft", "-j", "list", "set", "inet", "filter", nftSet)
	if err != nil {
		resp.WhitelistError = cmdError(err, out).Error()
	} else {
		resp.Whitelist = json.RawMessage(out)
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
