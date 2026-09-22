// Package reqip resolves the real client IP for a request reaching Herald
// through host-nginx.
package reqip

import (
	"net"
	"net/http"
	"strings"
)

// Source returns the caller's IP. X-Forwarded-For/X-Real-IP are trusted
// only when the immediate TCP peer is nginx itself (127.0.0.1/::1) -
// Herald is never meant to be reached directly, so any other peer is
// treated as the real, untrusted source and its headers are ignored.
func Source(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	if host != "127.0.0.1" && host != "::1" {
		return host
	}

	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		// A comma-separated list's first entry is the original client.
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = v[:i]
		}
		return strings.TrimSpace(v)
	}

	return host
}
