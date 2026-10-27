package actions

import (
	"fmt"
	"net/http"

	"github.com/eocrospoma/herald/internal/reqip"
)

// RevokeAll handles POST /herald/revoke-all: clears every IP from Herald's
// managed block of whitelist.conf (the hand-maintained entries above the
// markers - VPN/LAN subnets etc. - are untouched) and reloads nginx. POST,
// not GET, specifically because it's destructive and shouldn't be
// bookmarkable or end up in a GET history by accident.
func (a *Actions) RevokeAll(w http.ResponseWriter, r *http.Request) {
	ip := reqip.Source(r)

	err := a.applyWhitelistChange(func(wf *whitelistFile) {
		wf.clear()
	})
	if err != nil {
		http.Error(w, "failed to revoke", http.StatusInternalServerError)
		a.logError("revoke-all", ip, err)
		return
	}

	fmt.Fprintln(w, "all whitelisted IPs revoked")
}
