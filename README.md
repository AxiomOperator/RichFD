# RichFD

A web UI for managing **firewalld**: zones, policies, services, ports, protocols, ICMP, forwarding/NAT,
interface and source bindings, IP sets, and especially **rich rules**, with a visual builder that firewalld
itself validates as you type. One install manages its own host, and can also act as a console for other hosts.

- **Backend:** FastAPI talking to firewalld over D-Bus through the official `firewall.client` bindings. Rich rules
  are parsed and validated with firewalld's own `Rich_Rule` parser.
- **Frontend:** React, Vite, Tailwind CSS v4 and shadcn/ui, served by the backend as static files.
- **Auth:** PAM (system accounts). Admin and read-only roles come from Linux groups. Sessions use signed cookies
  with CSRF protection, and remote consoles authenticate with API tokens.

## Features

**Firewall management**
- **Zones and policies:** services, ports, protocols, source ports, ICMP blocks and inversion, masquerade,
  forward-ports, interfaces and sources. Policies add ingress/egress zones (including `HOST`/`ANY`), priority and
  target.
- **Rich rules:** a form builder plus raw mode, validated live. Rules can be edited, duplicated or made
  temporary, i.e. runtime-only with an expiry.
- **Bulk actions:** select rules or items, then delete them, copy/move them to another zone or policy, sync
  runtime ↔ permanent, or remove them from runtime only.
- **Custom services:** ports, protocols, source ports, conntrack helpers, includes and destination restrictions.
  Built-in services can be overridden and reset.
- **IP sets:** create them, add entries, and bulk-import address lists by pasting or from a file.
- **Rule templates:** SSH only from a subnet, rate-limited SSH, block a country (IP set downloaded from
  ipdeny.com or pasted in), port-forward to a container, block an address, allow a service from a source, and
  a web server preset. Every template shows a preview before it applies.
- **Runtime vs permanent:** each change goes to *Runtime + Permanent*, *Runtime only* or *Permanent only*. Items
  that differ between the two are flagged, with a one-click sync.

**Safety**
- **Config history:** a git snapshot of `/etc/firewalld` is taken around every change, labeled with who made it.
  The History page shows diffs, a restore preview and one-click restore (which reloads firewalld).
- **Lock-out warnings:** before a change is applied, current SSH sessions and your browser connection are
  simulated against the firewall as it is now and as it would be after the change. If any of them would be cut
  off, safe apply becomes mandatory. Risky changes are also flagged, such as a DROP target on an active zone or
  removing ssh or bindings. If the check itself fails, you're asked before anything is applied.
- **Safe apply:** the change is applied at runtime and auto-reverts after 60s unless you confirm it.
- **Atomic batches:** a multi-step change either fully applies or is rolled back.

**Diagnostics**
- **Traffic tester ("why is this blocked?"):** enter a source, protocol, port and interface. The tester shows
  which zone the traffic lands in, then walks through policies, rich rules in firewalld's order, services and
  ports, and the zone target, ending in a verdict and the step that decided it.
- **Live packet log:** log-denied entries and rich-rule `log` entries are streamed from the kernel journal, with
  filters and top sources. Each entry has buttons to explain it in the tester or to create an allow rule, which
  opens the builder pre-filled.
- **Direct rules:** a read-only view of deprecated direct rules, chains and passthroughs.

**Operations**
- **Change notifications:** every change, including outside changes, can be sent to a webhook
  (Slack/Mattermost-compatible), syslog or email.
- **Outside changes:** changes made with `firewall-cmd`, by editing XML files or by other tools are detected
  every 30s. Runtime changes are diffed, permanent ones are committed to history, and both are audited and
  notified.
- **Import/export:** JSON bundles, native firewalld XML for a single zone, policy, service or IP set, and a tar.gz
  of `/etc/firewalld`. Imports show a per-object preview (create, update or unchanged) before anything is
  applied.
- **Roles:** the `wheel` group gets full access and `firewall-viewers` gets read-only access (both configurable).
- **Multiple hosts:** any install can manage other installs. On each remote host, create an agent token, then
  add the host on the console's Hosts page and pick it in the sidebar. API calls, including the live log, are
  proxied, and the remote audit log records `console-user@token`.
- **HTTPS:** built-in TLS (`install.sh --tls`), or the ready-made Caddy/nginx configs in `deploy/`.
- **Audit log:** every change and login, as JSON lines, viewable in the UI.

## Install

```sh
sudo ./deploy/install.sh                        # 127.0.0.1:8443, plain HTTP (use an SSH tunnel)
sudo ./deploy/install.sh --tls                  # + self-signed certificate, HTTPS
sudo ./deploy/install.sh --tls --listen 0.0.0.0 # reachable from the network, e.g. as an agent
```

The install script:
- builds the frontend and installs everything to `/opt/richrule`;
- creates a venv with `--system-site-packages` (for the RPM-provided `python3-firewall` / `python3-dbus`);
- installs `/etc/pam.d/richrule` (password-only PAM, so fingerprint readers can't stall web logins);
- enables `richrule.service`.

The service runs as root, because PAM, firewalld writes, `/etc/firewalld` snapshots and the kernel log all need
it. Settings live in **`/etc/richrule/richrule.env`**, which is created once and never overwritten:

| Variable | Default | |
|---|---|---|
| `RICHRULE_HOST` / `RICHRULE_PORT` | `127.0.0.1` / `8443` | Listen address |
| `RICHRULE_ALLOWED_GROUP` | `wheel` | Full access |
| `RICHRULE_VIEWER_GROUP` | `firewall-viewers` | Read-only access (`groupadd firewall-viewers`) |
| `RICHRULE_TLS_CERT` / `RICHRULE_TLS_KEY` | — | Built-in HTTPS; secure cookies are enabled automatically |
| `RICHRULE_SECURE_COOKIES` | `0` | Set `1` behind a TLS reverse proxy |
| `RICHRULE_WATCH_INTERVAL` | `30` | Seconds between checks for outside changes (`0` = off) |
| `RICHRULE_SAFE_APPLY_SECONDS` | `60` | Safe-apply revert timeout |
| `RICHRULE_SESSION_IDLE_SECONDS` | `1800` | Idle session timeout |
| `RICHRULE_STATE_DIR` | `/var/lib/richrule` | History repo, tokens, hosts, notification settings |

Notification channels, agent tokens and remote hosts are configured in the UI (Settings and Hosts).

### Multiple hosts

1. On each managed host: `sudo ./deploy/install.sh --tls --listen 0.0.0.0`. Allow port 8443/tcp only from the
   console, for example with a rich rule.
2. On that host, go to Settings → Agent tokens → create a token. Or from a shell:
   `sudo /opt/richrule/backend/.venv/bin/python -m app.tokens create console`
   (run from `/opt/richrule/backend`).
3. On the console, go to Hosts → add the URL and the token. For a self-signed certificate, paste
   `/etc/richrule/tls/cert.pem` as the custom CA.
4. Choose the host in the sidebar's host switcher.

## Development

```sh
# backend
cd backend
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest                      # unit + API tests (in-memory fake firewalld, no root needed)

# DEV ONLY: skips PAM, so any username/password logs in (RICHRULE_DEV_ROLE=viewer to test read-only).
RICHRULE_DEV_USER=dev RICHRULE_PORT=8543 RICHRULE_STATE_DIR=/tmp/rr-state \
  RICHRULE_AUDIT_LOG=/tmp/rr-audit.log RICHRULE_SECRET_FILE=/tmp/rr-secret .venv/bin/python -m app.main

# frontend: hot reload on :5173, proxies /api to :8443 (edit vite.config.ts for another port)
cd frontend && npm install && npm run dev
```

Running as a normal user, reads work, while config history and the tar export are unavailable. Whether writes
work depends on polkit: on Fedora Workstation, an active local session of a `wheel` user may change firewalld.
API docs are served at `/api/docs`.

## Layout

```
backend/app/
  fw.py          firewalld D-Bus wrapper: zones, policies, services, ipsets, direct; atomic apply + undo
  richrule.py    structured rule model <-> rule strings (firewalld's Rich_Rule)
  history.py     git snapshots of /etc/firewalld, restore, outside-change detection (watcher thread)
  changes.py     wraps every API change: snapshot + audit (+ notifications)
  tester.py      "why is this blocked?" evaluator
  risk.py        lock-out analysis (tester before/after the change)
  denied.py      kernel packet-log parsing and live stream
  transfer.py    import/export (JSON bundle, firewalld XML, tar.gz, address lists)
  templates.py   rule templates
  notify.py      webhook / syslog / email
  hosts.py       multi-host console proxy;  tokens.py  agent API tokens
  safe_apply.py  auto-reverting runtime changes;  auth.py  PAM, roles, sessions, CSRF, tokens
  routers/       REST endpoints (/api/...)
frontend/src/
  components/RuleSet.tsx           zone/policy tabs, rich rules card, bulk actions
  components/RichRuleBuilder.tsx   builder + raw mode with live validation
  lib/risk.tsx  lib/zone-ops.ts    lock-out gate; runtime/permanent-aware changes
  pages/                           Dashboard, Zone, Policies, Tester, Denied, History, Templates, ...
deploy/          install.sh, richrule.service, richrule.env, pam.d-richrule, Caddyfile, nginx-richrule.conf
```
