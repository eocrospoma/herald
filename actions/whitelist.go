package actions

import (
	"fmt"
	"net"
	"net/http"

	"github.com/eocrospoma/herald/internal/reqip"
)

// Whitelist handles GET /herald/wl: adds the request's own source IP to
// the nftables set with a native per-element timeout. Reapplying the same
// IP just refreshes the timeout - idempotent by construction, no separate
// revocation scheduler needed in Herald itself.
func (a *Actions) Whitelist(w http.ResponseWriter, r *http.Request) {
	ip := reqip.Source(r)

	// The set element becomes a literal nft command argument below. nft
	// isn't invoked through a shell, so this isn't shell injection, but a
	// malformed value would still corrupt the nft syntax - validate it's
	// actually an IP first regardless.
	if net.ParseIP(ip) == nil {
		http.Error(w, "could not determine a valid source IP", http.StatusBadRequest)
		a.logError("wl", ip, fmt.Errorf("unparseable source IP %q", ip))
		return
	}

	elem := fmt.Sprintf("{ %s timeout %s }", ip, whitelistTimeout)
	out, err := a.Runner.Run("sudo", "nft", "add", "element", "inet", "filter", nftSet, elem)
	if err != nil {
		http.Error(w, "failed to whitelist", http.StatusInternalServerError)
		a.logError("wl", ip, cmdError(err, out))
		return
	}

	fmt.Fprintf(w, "whitelisted %s for %s\n", ip, whitelistTimeout)
}
