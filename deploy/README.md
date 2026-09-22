# Sentinel deployment recipes

Ready-to-install units, example configs, and env templates. The canonical
narrative lives in the [Deployment chapter of the main
README](../README.md#deployment); this directory holds the actual files.

```
deploy/
├── systemd/
│   ├── sentinel-hub.service        # control server: gRPC + REST + dashboard
│   ├── sentinel-daemon.service     # control server: scans the hub's own logs
│   └── sentinel-agent.service      # monitored VPS: forwarder (hardened, non-root)
├── config/
│   ├── hub.example.yaml            # -> /etc/sentinel/hub.yaml
│   └── agent.example.yaml          # -> /etc/sentinel/agent.yaml
└── env/
    └── hub.env.example             # -> /etc/sentinel/hub.env (DATABASE_URL)
```

Conventions used below: binary at `/usr/local/bin/sentinel`, config in
`/etc/sentinel/`, unprivileged `sentinel` system user, hub agents reach
over the [Tailscale](https://tailscale.com) tailnet (`100.64/10`).

## Control server (hub [+ daemon])

```bash
# build (needs protoc) — or install a release binary built in CI
cargo build --release
sudo install -m 0755 target/release/sentinel /usr/local/bin/sentinel
sudo mkdir -p /opt/sentinel/web
sudo cp -r web/dist /opt/sentinel/web/dist

# user + config skeleton
sudo useradd --system --home /etc/sentinel --shell /usr/sbin/nologin sentinel
sudo mkdir -p /etc/sentinel
sudo cp deploy/config/hub.example.yaml /etc/sentinel/hub.yaml    # edit IPs/paths
sudo cp deploy/env/hub.env.example /etc/sentinel/hub.env         # set DATABASE_URL
sudo chown -R sentinel:sentinel /etc/sentinel
sudo chmod 600 /etc/sentinel/hub.env

# Postgres (hub runs migrations itself on startup)
sudo -u postgres createuser sentinel --no-createdb
sudo -u postgres createdb -O sentinel sentinel
# ...then set a password and put the URL into /etc/sentinel/hub.env

# units
sudo cp deploy/systemd/sentinel-hub.service deploy/systemd/sentinel-daemon.service \
        /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-hub
curl -s localhost:8080/v1/health

# monitor the control server's own logs too (the hub never scans locally)
sudo systemctl enable --now sentinel-daemon

# one API key per monitored VPS (raw key printed exactly once)
sudo -u sentinel sh -c '. /etc/sentinel/hub.env; sentinel hub-key create --agent vps1'
# a dashboard-unlock key for the SPA:
sudo -u sentinel sh -c '. /etc/sentinel/hub.env; sentinel hub-key create --dashboard "ops"'
```

## Monitored VPS (agent)

No Postgres, no build toolchain — copy the release binary over.

```bash
sudo useradd --system --home /etc/sentinel --shell /usr/sbin/nologin sentinel
sudo install -m 0755 sentinel /usr/local/bin/sentinel   # scp'd from the hub/CI

sudo mkdir -p /etc/sentinel
sudo cp deploy/config/agent.example.yaml /etc/sentinel/agent.yaml   # set hub_addr
printf 'snt_...\n' | sudo tee /etc/sentinel/agent.key >/dev/null    # the key from the hub
sudo chown -R sentinel:sentinel /etc/sentinel
sudo chmod 600 /etc/sentinel/agent.key /etc/sentinel/agent.yaml

# host-log reads: the unit adds the sentinel user to `adm` (Debian/Ubuntu
# nginx/auth logs). On other layouts, grant read access some other way.
sudo usermod -aG adm sentinel

# OPTIONAL: Docker log forwarding — do NOT add sentinel to the docker group
# (group membership is root-equivalent). Grant read-only ACLs instead; the
# default ACL makes new container logs inherit access:
sudo setfacl -m u:sentinel:x /var/lib/docker
sudo setfacl -R -m u:sentinel:rX /var/lib/docker/containers
sudo setfacl -R -d -m u:sentinel:rX /var/lib/docker/containers
# re-run the setfacl lines after major Docker upgrades

sudo cp deploy/systemd/sentinel-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-agent
journalctl -u sentinel-agent -f
```

Verify in the hub dashboard: the host appears with metrics, container logs,
and parsed `log_entries` tagged with its `source_host`.

## Upgrading

```bash
# control server
git pull && cargo build --release
sudo install -m 0755 target/release/sentinel /usr/local/bin/sentinel
sudo systemctl restart sentinel-hub        # migrations run automatically
sudo systemctl restart sentinel-daemon     # if co-installed

# client VPSes — AFTER the hub is upgraded (old hubs ignore the additive
# parsed_lines field; upgrade order: hub first, then agents)
scp target/release/sentinel vps:/usr/local/bin/sentinel
ssh vps sudo systemctl restart sentinel-agent
```

Releases that add a `migrations/` file need no manual step for the hub;
for a daemon running without a hub on the same host, run
`cargo sqlx migrate run` (or restart the hub first — it migrates).

## Notes on the hardened units

- All three units run as the `sentinel` user with
  `ProtectSystem=strict` (read-only filesystem; log tailing only needs
  reads) and a full capability drop.
- The agent unit restricts outbound sockets to loopback + the
  `100.64/10` tailnet range (`IPAddressAllow`); comment those out if your
  hub sits elsewhere or systemd lacks BPF support.
- If you enable `hub.tls.enabled`, add the cert/key files to the hub
  unit's `ReadOnlyPaths`.
- Older systemd (< 240) may lack some `Protect*` directives; drop the
  unsupported lines rather than the unit.
