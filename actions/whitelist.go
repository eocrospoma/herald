package actions

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/eocrospoma/herald/internal/reqip"
)

// Whitelist handles GET /herald/wl: adds the request's own source IP to
// nginx's whitelist.conf (in Herald's managed block only) and reloads
// nginx. Reapplying the same IP just refreshes its expiry - idempotent by
// construction from the caller's point of view, even though a background
// sweeper (see nginx_whitelist.go) is what actually revokes it later.
func (a *Actions) Whitelist(w http.ResponseWriter, r *http.Request) {
	ip := reqip.Source(r)

	if net.ParseIP(ip) == nil {
		http.Error(w, "could not determine a valid source IP", http.StatusBadRequest)
		a.logError("wl", ip, fmt.Errorf("unparseable source IP %q", ip))
		return
	}

	now := time.Now()
	err := a.applyWhitelistChange(func(wf *whitelistFile) {
		wf.upsert(ip, now.Add(a.WhitelistTTL), now)
	})
	if err != nil {
		http.Error(w, "failed to whitelist", http.StatusInternalServerError)
		a.logError("wl", ip, err)
		return
	}

	fmt.Fprintf(w, "whitelisted %s for %s\n", ip, a.WhitelistTTL)
}
