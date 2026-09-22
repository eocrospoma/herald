package actions

import (
	"fmt"
	"net/http"

	"github.com/eocrospoma/herald/internal/reqip"
)

// ReloadBlog handles GET /herald/reload-blog: restarts the hardcoded
// "blog" systemd unit. No parameters by design - a new target would be a
// new verb, not a generic "restart {name}" action.
func (a *Actions) ReloadBlog(w http.ResponseWriter, r *http.Request) {
	ip := reqip.Source(r)

	out, err := a.Runner.Run("sudo", "systemctl", "restart", "blog")
	if err != nil {
		http.Error(w, "failed to restart blog", http.StatusInternalServerError)
		a.logError("reload-blog", ip, cmdError(err, out))
		return
	}

	fmt.Fprintln(w, "blog restarted")
}
