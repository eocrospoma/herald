package actions

import (
	"fmt"
	"net/http"

	"github.com/eocrospoma/herald/internal/reqip"
)

// RevokeAll handles POST /herald/revoke-all: clears every whitelisted IP.
// POST, not GET, specifically because it's destructive and shouldn't be
// bookmarkable or end up in a GET history by accident.
func (a *Actions) RevokeAll(w http.ResponseWriter, r *http.Request) {
	ip := reqip.Source(r)

	out, err := a.Runner.Run("sudo", "nft", "flush", "set", "inet", "filter", nftSet)
	if err != nil {
		http.Error(w, "failed to revoke", http.StatusInternalServerError)
		a.logError("revoke-all", ip, cmdError(err, out))
		return
	}

	fmt.Fprintln(w, "all whitelisted IPs revoked")
}
