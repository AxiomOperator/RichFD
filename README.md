# RichFD

A web UI for managing the local host's **firewalld**: zones, services, ports, protocols, ICMP, forwarding/NAT,
interface and source bindings, IP sets, and especially **rich rules**, with a visual builder that firewalld
itself validates as you type.

- **Backend:** FastAPI talking to firewalld over D-Bus through the official `firewall.client` bindings. Rich rules
  are parsed and validated with firewalld's own `Rich_Rule` parser.
- **Frontend:** React, Vite, Tailwind CSS v4 and shadcn/ui, served by the backend as static files.
- **Auth:** PAM (system accounts), restricted to one group (default `wheel`), with signed session cookies and CSRF
  protection.

## Features

- **Runtime vs permanent:** each change goes to *Runtime + Permanent* (default), *Runtime only*, or *Permanent
  only*, selected in the header. Items that exist in only one config are flagged, and one click syncs them.
- **Safe apply:** the change is applied at runtime and auto-reverts after 60s unless you click **Keep change**.
  This protects you from locking yourself out.
- **Temporary rules:** runtime-only rich rules that firewalld expires after N seconds.
- **Atomic batches:** a multi-step change (e.g. editing a rule, which removes it and adds the new one) either
  fully applies or is rolled back.
- **Audit log:** every change and login is appended as JSON lines to `/var/log/richrule/audit.log` and can be
  viewed in the UI.
- Reload, runtime→permanent, panic mode, log-denied, default zone, zone create/delete/reset, and IP sets.

## Install (production)

```sh
sudo ./deploy/install.sh
```

This builds the frontend, installs to `/opt/richrule`, creates a venv with `--system-site-packages` (for the
RPM-provided `python3-firewall` / `python3-dbus`), and enables `richrule.service`. The service runs as root,
because PAM password checks and firewalld writes need it, and binds to **127.0.0.1:8443** only.

Reach it from another machine with an SSH tunnel:

```sh
ssh -L 8443:127.0.0.1:8443 yourserver    # then open http://localhost:8443
```

Or put it behind a TLS reverse proxy and set `RICHRULE_SECURE_COOKIES=1`.

### Configuration

Set these environment variables in `deploy/richrule.service`:

| Variable | Default | |
|---|---|---|
| `RICHRULE_HOST` / `RICHRULE_PORT` | `127.0.0.1` / `8443` | Listen address |
| `RICHRULE_ALLOWED_GROUP` | `wheel` | Only members of this group can log in |
| `RICHRULE_PAM_SERVICE` | `richrule` | PAM service used to check passwords (`/etc/pam.d/richrule`, password-only so fingerprint readers don't stall logins) |
| `RICHRULE_SESSION_IDLE_SECONDS` | `1800` | Idle session timeout |
| `RICHRULE_SAFE_APPLY_SECONDS` | `60` | Safe-apply revert timeout |
| `RICHRULE_SECURE_COOKIES` | `0` | Set `1` when served over HTTPS |
| `RICHRULE_AUDIT_LOG` | `/var/log/richrule/audit.log` | |
| `RICHRULE_SECRET_FILE` | `/var/lib/richrule/secret.key` | Session signing key (auto-created) |

## Development

```sh
# backend
cd backend
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest                      # unit + API tests (in-memory fake firewalld, no root needed)

# DEV ONLY: skips PAM, so any username/password logs in. Never expose this.
RICHRULE_DEV_USER=dev RICHRULE_AUDIT_LOG=/tmp/rr-audit.log RICHRULE_SECRET_FILE=/tmp/rr-secret \
  .venv/bin/python -m app.main

# frontend (second terminal): hot reload on :5173, proxies /api to :8443
cd frontend && npm install && npm run dev
```

Reads work as a normal user. Whether writes work depends on the polkit policy. On Fedora Workstation, an active
local session of a `wheel` user may change firewalld without a prompt.

API docs are served at `/api/docs` while the backend runs.

## Layout

```
backend/app/
  fw.py          firewalld D-Bus wrapper: generic add/remove Ops, runtime/permanent, atomic apply + undo
  richrule.py    structured rule model <-> rule strings, validated by firewalld's Rich_Rule
  safe_apply.py  pending runtime change with auto-revert timer
  auth.py        PAM + group check, sessions, CSRF, login rate limiting
  audit.py       JSON-lines audit log
  routers/       REST endpoints (/api/...)
frontend/src/
  components/RichRuleBuilder.tsx   builder + raw mode with live validation
  pages/Zone.tsx                   zone detail tabs
  lib/zone-ops.ts                  runtime/permanent merge + apply-mode aware changes
deploy/          systemd unit + install script
```
