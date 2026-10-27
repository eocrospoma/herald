package actions

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// nginx's whitelist.conf predates Herald and holds a mix of long-lived,
// hand-maintained entries (VPN/LAN subnets, a few sticky IPs with their own
// comments) that Herald must never touch, plus - between two sentinel
// marker lines - the IPs Herald itself whitelists on request. Herald only
// ever rewrites what's between those markers; everything else is
// preserved byte-for-byte. See deploy/nginx-whitelist-markers.md for the
// one-time migration that adds the markers to a pre-existing file.
const (
	managedBeginMarker = "# --- herald-managed (do not edit below by hand) ---"
	managedEndMarker   = "# --- end herald-managed ---"
)

// entryLineRe matches a line Herald itself wrote: "allow <ip>; # herald-wl
// expires=<RFC3339>". Anything in the managed block NOT matching this is a
// parse error - better to refuse than to silently drop or misread an entry
// in a file that gates access to the sensitive vhosts.
var entryLineRe = regexp.MustCompile(`^allow (\S+); # herald-wl expires=(\S+)$`)

type whitelistEntry struct {
	IP      string
	Expires time.Time
}

// whitelistFile is whitelist.conf split into the part before (and
// including) the begin marker, the parsed managed entries, and the part
// from the end marker onward. Rendering it back out reproduces the
// original file exactly except for the managed entries themselves.
type whitelistFile struct {
	beforeLines []string
	entries     []whitelistEntry
	afterLines  []string
}

func loadWhitelistFile(path string) (*whitelistFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	beginIdx := indexOfLine(lines, managedBeginMarker)
	endIdx := indexOfLine(lines, managedEndMarker)
	if beginIdx == -1 || endIdx == -1 || endIdx < beginIdx {
		return nil, fmt.Errorf("%s is missing the herald-managed markers - see deploy/nginx-whitelist-markers.md", path)
	}

	var entries []whitelistEntry
	for _, line := range lines[beginIdx+1 : endIdx] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		m := entryLineRe.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("unrecognized line in the herald-managed block of %s: %q", path, line)
		}
		expires, err := time.Parse(time.RFC3339, m[2])
		if err != nil {
			return nil, fmt.Errorf("invalid expires timestamp in %s: %q: %w", path, line, err)
		}
		entries = append(entries, whitelistEntry{IP: m[1], Expires: expires})
	}

	return &whitelistFile{
		beforeLines: lines[:beginIdx+1],
		entries:     entries,
		afterLines:  lines[endIdx:],
	}, nil
}

func indexOfLine(lines []string, target string) int {
	for i, l := range lines {
		if l == target {
			return i
		}
	}
	return -1
}

func (f *whitelistFile) render() string {
	var sb strings.Builder
	for _, l := range f.beforeLines {
		sb.WriteString(l)
		sb.WriteByte('\n')
	}
	for _, e := range f.entries {
		fmt.Fprintf(&sb, "allow %s; # herald-wl expires=%s\n", e.IP, e.Expires.UTC().Format(time.RFC3339))
	}
	for _, l := range f.afterLines {
		sb.WriteString(l)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// prune drops entries that have already expired.
func (f *whitelistFile) prune(now time.Time) {
	kept := f.entries[:0]
	for _, e := range f.entries {
		if e.Expires.After(now) {
			kept = append(kept, e)
		}
	}
	f.entries = kept
}

// upsert prunes expired entries, then adds ip with a fresh expiry, or
// refreshes it if already present - reapplying the same IP just extends
// its window, matching the original nftables design's idempotent-by-tap
// behavior.
func (f *whitelistFile) upsert(ip string, expires, now time.Time) {
	f.prune(now)
	for i, e := range f.entries {
		if e.IP == ip {
			f.entries[i].Expires = expires
			return
		}
	}
	f.entries = append(f.entries, whitelistEntry{IP: ip, Expires: expires})
}

func (f *whitelistFile) clear() {
	f.entries = nil
}

// applyWhitelistChange loads the file, lets mutate edit the parsed
// entries, and - only if that actually changed the rendered content -
// writes it back (atomically, via rename), validates the result with
// `nginx -t`, and reloads nginx. Callers never write or reload directly;
// this is the one path that does, serialized by whitelistMu.
func (a *Actions) applyWhitelistChange(mutate func(*whitelistFile)) error {
	a.whitelistMu.Lock()
	defer a.whitelistMu.Unlock()

	wf, err := loadWhitelistFile(a.WhitelistPath)
	if err != nil {
		return err
	}

	before := wf.render()
	mutate(wf)
	after := wf.render()

	if before == after {
		return nil
	}

	if err := writeAtomic(a.WhitelistPath, after); err != nil {
		return err
	}

	if out, err := a.Runner.Run("sudo", "nginx", "-t"); err != nil {
		// The live file must never be left in a state that failed
		// validation - roll back to what was there before.
		if rbErr := writeAtomic(a.WhitelistPath, before); rbErr != nil {
			return fmt.Errorf("nginx -t failed (%v) AND rolling back %s failed (%v) - it is now in an unknown state", cmdError(err, out), a.WhitelistPath, rbErr)
		}
		return fmt.Errorf("nginx -t failed after updating %s (rolled back): %w", a.WhitelistPath, cmdError(err, out))
	}

	if out, err := a.Runner.Run("sudo", "systemctl", "reload", "nginx"); err != nil {
		// nginx -t already passed, so the written file is valid - just not
		// live yet. Leave it in place; the next successful reload (or the
		// next sweep) picks it up.
		return fmt.Errorf("reloading nginx: %w", cmdError(err, out))
	}
	return nil
}

func writeAtomic(path, content string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", tmp, path, err)
	}
	return nil
}

// SweepExpiredWhitelist drops any expired entries and reloads nginx only
// if that actually removed something. Intended to be called periodically
// (see main.go) so revocation doesn't depend on another /herald/wl or
// /herald/status call happening to trigger it.
func (a *Actions) SweepExpiredWhitelist() error {
	return a.applyWhitelistChange(func(wf *whitelistFile) {
		wf.prune(time.Now())
	})
}
