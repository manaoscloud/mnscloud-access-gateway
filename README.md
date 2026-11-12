# mnscloud-access-gateway

MNSCloud access gateway: the runtime that opens remote-support sessions to customer network devices
(SSH terminal, RouterOS API "Testar acesso") from dedicated hosts, one sandbox per session. The App
shows the terminal; the API decides who may connect where; the gateway only relays, classifies and
redacts.

```text
App (browser) ──wss──▶ edge nginx ──TLS 7443──▶ controller ──pipe──▶ worker (sandbox) ──SSH / API-SSL──▶ device
                                                    │
                                                    ├─ API /access/runtime/* (host Agent identity)
                                                    └─ OpenVault unwrap (single-use token per connection)
```

## How it works

- **Controller** (`mnscloud-access-gateway.service`, root): reads the node binding, authenticates to
  the API with the identity of the enrolled host Agent (no credential of its own), applies the host
  firewall from `/config`, long-polls assignments, serves the browser WebSocket on port 7443 (TLS,
  only from the edge hosts, only with a single-use ticket whose SHA-256 the API sent in the
  assignment) and pulls the device credential when the worker asks for it.
- **Worker** (one per connection): a transient systemd service in its own network namespace, with a
  dynamic user, no capabilities, no new privileges, read-only system, memory/CPU/task/time limits, a
  cgroup IP filter and Deno `--allow-net=<device ip>:<port>`. It speaks SSH (PTY) or the RouterOS
  API over TLS, verifies the host key (or certificate) **before** any authentication, and receives
  the credential over its stdin pipe (memory only).
- **Policy** (manual mode): the worker keeps a shadow line buffer of what the operator types and
  classifies each line on Enter with data-driven rules per dialect (`rules/routeros.json`,
  `linux.json`, `proxmox.json`, `vrp.json`, `other.json`): `read`, `write_low`, `write_risky`,
  `destructive`, `pivot`, `secret_read`. Reads run; writes wait for confirmation in the App;
  destructive commands need two confirmations and level N3; pivots need N3; secret reads are always
  blocked. Lines edited with arrows, Tab, history or other escapes, and anything the rules do not
  recognize, are `unknown` and treated as `write_risky` (fail-closed).
- **Redaction**: device output is sanitized (OSC/DCS/APC sequences dropped) and secrets are masked
  before anything leaves the worker (browser, recording, command events): `password=`/`secret=`/
  `*-key=` values, VRP `cipher %^%#...`, private key blocks, crypt hashes, URL passwords and the
  session's own secret. Partial lines are flushed after 50 ms, holding back anything that could still
  become a secret.
- **Recording**: asciicast v2 of the redacted output with markers for each command verdict (never
  keystrokes), uploaded in parts of about 1 MB / 60 s; the API stores it in Storage (90 days).

## What the gateway can and cannot reach

| Reaches                                                     | Never reaches                                                                                                    |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| The MNSCloud API (HTTPS, host Agent identity)               | Platform networks (DEV/PROD), management VPN ranges, MNSCloud public blocks (`denylist` of `/config`)            |
| OpenVault, only to unwrap the per-connection token          | RFC 1918, RFC 6598, loopback, link-local incl. 169.254.169.254, multicast, documentation, NAT64/6to4/Teredo, ULA |
| The one device IP:port of each session, resolved by the API | Any name (no DNS for sessions), any other port or address, Telnet (23) and plain RouterOS API (8728)             |

Three layers enforce the device-only rule: the namespace nftables table (output only to IP:port), the
host forward path (denylist dropped before the per-session allow set; DEV lab /32 targets are the
only exception and only in development) and the worker's Deno permission. The listener accepts only
the edge hosts (`edgeSources`) — host nftables and the controller both check.

The gateway never runs a local shell or program on behalf of an operator or the AI, holds no platform
secret (database, RabbitMQ, JWT) and keeps no device credential after the connection. A device can
of course print its own configuration in obfuscated forms the patterns cannot recognize; redaction
protects against known secret formats, not against a hostile device.

## Install (bootstrap)

Requirements: a dedicated Debian 12/13 VM with the MNSCloud Agent installed and enrolled, its own
VLAN, a private address the edge reaches on TCP 7443 and the fixed public egress address of the
environment.

1. In the App, **Sistema › Gateways de acesso**, create the gateway and generate the installation
   command (single use, 30 minutes, pinned to the approved release).
2. Run the command on the gateway host. It clones this repository, checks out the approved tag and
   runs `scripts/install-access-gateway.sh`, which installs Deno from `mnscloud-runtime-kit`, claims
   the installation with the host Agent (the token goes only through stdin), writes
   `/etc/mnscloud/access-gateway.env`, creates the listener certificate, the controller unit and the
   forwarding sysctl, starts the controller and runs `scripts/validate-access-gateway.sh`. The result
   is reported to the App.
3. A failed attempt shows **Retry installation** in the App; the resume command has no token.

## Remote access connector (tenant network path)

The public path reaches devices that are routable from the internet. For devices on a private LAN or
behind CGNAT the tenant installs a **connector**: a small runtime on a Debian 12/13 or Ubuntu
22.04/24.04 host (amd64 or arm64) inside its own network. It opens an outbound tunnel to the access
gateway the platform assigned to it, and the gateway reaches the device through it.

- **Requirements**: outbound HTTPS (TCP 443) to the platform API and to the assigned gateway's public
  host; a route from the connector host to the devices (SSH 22 or the RouterOS API-SSL port). No
  inbound port, no VPN, no port forwarding.
- **What it reaches**: only a device the API confirmed for that exact connection (connection,
  address, port, this connector, single use). Private ranges of the tenant are allowed; if the tenant
  set allowed networks on the connector, only those. **What it never reaches**: loopback, link-local
  (including 169.254.169.254), multicast, unspecified and broadcast addresses, the connector host
  itself, Telnet (23) and the plain RouterOS API (8728).
- **What it is not**: it holds no platform secret (its identity is an Ed25519 key generated on the
  host; only the public key leaves it), never executes commands, never listens on a port, and cannot
  start anything toward the platform: only the gateway opens streams over the tunnel, and the gateway
  never forwards packets (the stream ends inside the sandboxed worker's own SSH/TLS client, which has
  no network at all).
- **Install**: in the App, **Rede › Conectores**, create the connector and use **Instalar**. The
  command downloads `scripts/install-connector.sh` of an approved release, checks its SHA-256 and
  runs it with a single-use token (24 h) in the environment. The service runs as the unprivileged
  `mns-connector` user (`NoNewPrivileges`, `ProtectSystem=strict`, no capabilities); a root timer
  applies the release the platform announces (the tag must resolve to the announced commit; a release
  that does not start is rolled back).
- **Uninstall**: `sudo /opt/mnscloud-access-connector/scripts/uninstall-connector.sh`, then delete the
  connector in the App.

The connector code is `src/connector/`, the gateway side is `src/controller/connector_hub.ts` and
`src/controller/bridge.ts`, the frame format `src/shared/tunnel.ts`. Wire contract, signatures and
test vectors: `docs/runtime-api.md` → Remote access connector.

## Update and rollback

MNSCloud delivery (maintainers and AI agents) is the Agent rollout:

```bash
# workspace host, /opt/mnscloud
scripts/ops/rollout.sh dev mnscloud-access-gateway
```

The Agent checks out the approved tag and runs `scripts/update-access-gateway.sh --env
/etc/mnscloud/access-gateway.env`, which type-checks the vendored runtime offline, rewrites the unit,
restarts the controller (open sessions end; the App reconnects with a new ticket) and validates; a
failed validation restores the last good release.

Bootstrap or authorized recovery on the gateway host only:

```bash
sudo /opt/mnscloud/mnscloud-access-gateway/scripts/update-latest-access-gateway.sh
sudo /opt/mnscloud/mnscloud-access-gateway/scripts/rollback-access-gateway.sh --ref <previous-approved-tag>
sudo /opt/mnscloud/mnscloud-access-gateway/scripts/validate-access-gateway.sh
```

## Files on the host

| Path                                            | Content                                                                           |
| ----------------------------------------------- | --------------------------------------------------------------------------------- |
| `/opt/mnscloud/mnscloud-access-gateway`         | this repository at the approved tag (world-readable, not writable)                |
| `/etc/mnscloud/access-gateway.env`              | binding: API base, gateway UUID/key, listen address/port (0600, no secret)        |
| `/etc/mnscloud/access-gateway/tls/`             | listener certificate and key (0600; the public certificate is pinned by the edge) |
| `/var/lib/mnscloud/access-gateway/`             | last good release commit                                                          |
| `/etc/sysctl.d/90-mnscloud-access-gateway.conf` | IPv4/IPv6 forwarding for the session namespaces                                   |
| nftables `inet mnscloud_access_gateway`         | host table (listener, forward denylist, session allow sets, masquerade)           |

`scripts/cleanup-sessions.sh` (run after the controller stops) removes every session unit and
namespace: no session survives the controller.

## Development

```bash
deno fmt --check && deno lint && deno task check && deno task test
shellcheck -x scripts/*.sh scripts/lib/*.sh
```

Tests run offline with the vendored dependencies: connector tunnel (frames, credit flow, handshake
signatures, destination checks, an end-to-end tunnel to a fake device), classifier and redaction fixtures, framing,
tickets, nftables/netns/systemd rendering, a hostile fake SSH device (host key change, output flood,
escape sequences, prompt-injection text) and a RouterOS API-SSL mock. The runtime API contract is
`docs/runtime-api.md`.

Dependencies (`ssh2` and its pure-JavaScript dependencies, `@types/node` for type checking) are
vendored in `node_modules/` and pinned by `deno.lock`; the runtime runs with `--cached-only --frozen`
and never downloads. Update them with `deno install` and commit the result.
