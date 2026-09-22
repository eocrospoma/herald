// Package audit writes Herald's append-only, JSON-Lines audit log: one
// object per request, greppable enough for a fail2ban filter to catch
// repeated unauthorized attempts by source IP.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Entry is a single audit-log record.
type Entry struct {
	Time     time.Time `json:"time"`
	Action   string    `json:"action"`
	SourceIP string    `json:"source_ip"`
	Result   string    `json:"result"` // "ok", "unauthorized", or "error"
	Detail   string    `json:"detail,omitempty"`
}

// Logger appends Entry records as JSON Lines to an underlying writer,
// serializing concurrent writes so lines never interleave.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

func NewLogger(w io.Writer) *Logger {
	return &Logger{w: w}
}

// Log writes e as one JSON line. Time defaults to now (UTC) if unset. A
// write failure is returned rather than swallowed, but callers should treat
// it as non-fatal - a request having already been authorized/handled
// shouldn't fail just because the audit log couldn't be written.
func (l *Logger) Log(e Entry) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	return json.NewEncoder(l.w).Encode(e)
}
