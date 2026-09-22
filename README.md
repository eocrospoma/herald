# herald

A small HTTP service exposing a fixed, closed set of TOTP-gated verbs for
managing access to this host from anywhere - most importantly, whitelisting
the caller's own IP into the host firewall.

## Design

- **Fixed verbs, no free-form parameters.** The URL path *is* the whole
  action. Adding a new privileged action means adding a new verb (one
  registry entry + one handler), not extending a generic "run this with
  these params" action - that generic shape is exactly what got removed
  from an earlier design, specifically to close off injection surface.
- **Auth is TOTP, hand-rolled (RFC 4226/6238), not a library.** HOTP =
  HMAC-SHA1(secret, big-endian 8-byte counter), RFC 4226 dynamic
  truncation, 6 digits. Verified against the current 30s time-step and its
  immediate neighbors (±30s clock-drift tolerance). Anti-replay tracks the
  *consumed time-step*, not the code value, in an in-memory map - a given
  step can only be spent once, even though only 10^6 code values exist and
  unrelated steps can coincidentally produce the same code.
- **Every path is meant to be fully public.** Bookmarked on a phone, even
  listed on a CV, without weakening security - the gate is "no valid TOTP,
  nothing happens," not obscurity. fail2ban on repeated 401s
  (`deploy/fail2ban/`) is defense-in-depth on top of that, not the real
  gate.
- **Runs directly on the host, deliberately not Kubernetes.** It mutates
  the host firewall and host services, which in k8s would need a
  privileged/hostNetwork pod (an anti-pattern); and as the
  emergency-access tool, it can't depend on the cluster it grants access
  to. It sits behind the existing host-nginx for TLS and a consistent
  access-log format.
- **Least privilege throughout:** a dedicated unprivileged user, one
  narrowly-scoped sudoers rule for the exact command lines Herald needs
  (see `deploy/sudoers.example`), systemd sandboxing
  (`deploy/herald.service`), and an append-only JSON-Lines audit log for
  every request.

## Verbs

| Path | Method | Does |
|---|---|---|
| `/herald/wl?code=NNNNNN` | GET | Whitelists the request's own source IP into an nftables set with a native per-element timeout (900s). Reapplying the same IP just refreshes the timeout - idempotent by construction, no separate revocation scheduler needed. |
| `/herald/reload-blog?code=NNNNNN` | GET | Restarts the hardcoded `blog` systemd unit. |
| `/herald/status?code=NNNNNN` | GET | Read-only: current whitelist contents (`nft -j list set`) + the last 20 audit-log entries. |
| `/herald/revoke-all` | POST (`code` in the form body) | Clears every whitelisted IP. POST, not GET, specifically because it's destructive and shouldn't be bookmarkable or end up in a GET history by accident. |

A path outside this table gets a 404 with zero side effects.

## Source IP resolution

Herald trusts `X-Forwarded-For`/`X-Real-IP` only when the immediate TCP
peer is `127.0.0.1`/`::1` (i.e. nginx itself) - otherwise it uses the raw
connection IP. Standard reverse-proxy trust-boundary hygiene, since Herald
is never meant to be reached directly.

## Deploying

1. `go build -o herald .`
2. Create a dedicated user: `useradd --system --no-create-home herald`
3. Copy `.env.example` to `/etc/herald/herald.env`, fill in a real
   `HERALD_TOTP_SECRET` (`openssl rand -base64 32`), lock down permissions.
4. Install `deploy/herald.service` to `/etc/systemd/system/`, `deploy/sudoers.example`
   to `/etc/sudoers.d/herald` (validate with `visudo -cf`), and the
   fail2ban filter/jail from `deploy/fail2ban/`.
5. Add an nginx vhost proxying to `HERALD_LISTEN_ADDR` (loopback-only by
   default - never expose Herald directly).
6. `systemctl enable --now herald`

## Testing

```
go test ./...
```

The TOTP core is checked against the official RFC 4226 Appendix D and
RFC 6238 Appendix B test vectors, plus drift/replay/purge behavior. The
privileged actions (`nft`, `systemctl`) run through an injectable
`Runner`, so `go test ./...` never shells out to a real command.
