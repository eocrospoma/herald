# One-time setup: whitelist.conf markers + permissions

Herald edits only the block between two marker lines in nginx's existing
`whitelist.conf` - everything else (VPN/LAN subnets, hand-added sticky
IPs) is preserved byte-for-byte. Before Herald's `/herald/wl` or
`/herald/revoke-all` can run for the first time, do this once.

## 1. Add the markers

`whitelist.conf` ends with a `deny all;` after its hand-maintained `allow`
lines. Insert the two marker lines immediately before that:

```diff
 allow 38.25.15.118; # erick mac, added 2026-09-06 for argocd
+# --- herald-managed (do not edit below by hand) ---
+# --- end herald-managed ---
 deny all;
```

Nothing else in the file changes. `sudo nginx -t` after editing, same as
any other nginx config change.

## 2. Let the herald user write the file without sudo

Herald writes this file directly (temp file + atomic rename in the same
directory), not through a sudo-wrapped command - sudo is reserved for the
two steps that actually need root (`nginx -t`, `systemctl reload nginx`;
see `sudoers.example`). For the write itself, give the `herald` group
write access to the file:

```
sudo chgrp herald /etc/nginx/sites-available/whitelist.conf
sudo chmod 664 /etc/nginx/sites-available/whitelist.conf
```

(`herald.service`'s `ReadWritePaths` also grants the `herald` user write
access to the whole `/etc/nginx/sites-available` directory, which the
temp-file-then-rename pattern needs - renaming requires creating a new
directory entry, not just modifying the target file's contents. This is
broader than just this one file; accepted as the standard systemd
sandboxing tradeoff for an atomic-write pattern, not a cue to widen the
sudoers rule - the sudoers rule stays scoped to `nginx -t`/`reload nginx`
regardless of what herald's own filesystem access covers.)

## 3. Verify

```
sudo -u herald nginx -t
```

should succeed, and manually appending a line in the managed block
followed by `sudo systemctl reload nginx` should take effect without
touching anything above the markers.
