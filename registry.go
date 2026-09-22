package main

import (
	"net/http"

	"github.com/eocrospoma/herald/audit"
	"github.com/eocrospoma/herald/internal/reqip"
)

// action is a privileged operation Herald exposes at a fixed path. It only
// ever runs after TOTP verification has already succeeded - the code
// parameter itself is not passed through, so an action has no way to skip
// authentication by construction.
type action = http.HandlerFunc

// route is one entry in the registry: the single HTTP method a path
// accepts, a short name used in audit-log entries (e.g. "wl", "status"),
// and the action to run once verified.
type route struct {
	method string
	name   string
	action action
}

// registry maps exact URL paths to their route. There is no pattern
// matching or free-form parameters beyond "code" - the path is the whole
// action, by design. A path outside this map gets a 404 with zero side
// effects, since unmatched paths never reach any handler below.
type registry map[string]route

// codeParam extracts the TOTP code: a query parameter for GET requests, a
// parsed form value for POST - so a destructive POST action's code never
// ends up in a URL, browser history, or an access log's request line.
func codeParam(r *http.Request) string {
	if r.Method == http.MethodPost {
		return r.FormValue("code")
	}
	return r.URL.Query().Get("code")
}

// handler builds the top-level http.Handler for the registry: method
// check, TOTP verification, then dispatch - with every request that
// reaches a registered path producing exactly one audit-log entry,
// authorized or not.
func (reg registry) handler(verifier *TOTPVerifier, log *audit.Logger) http.Handler {
	mux := http.NewServeMux()

	for path, rt := range reg {
		rt := rt // capture for the closure below
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			ip := reqip.Source(r)

			if r.Method != rt.method {
				w.Header().Set("Allow", rt.method)
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}

			if !verifier.Verify(codeParam(r)) {
				_ = log.Log(audit.Entry{Action: rt.name, SourceIP: ip, Result: "unauthorized"})
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			_ = log.Log(audit.Entry{Action: rt.name, SourceIP: ip, Result: "ok"})
			rt.action(w, r)
		})
	}

	return mux
}
