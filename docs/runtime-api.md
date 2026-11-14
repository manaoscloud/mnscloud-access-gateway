# Access gateway runtime API (contract)

The API implements these calls; the gateway (`src/controller/control_plane.ts`,
`src/controller/runtime_api.ts`, `src/bootstrap.ts`) is the client. The gateway validates every
response it reads (`src/controller/contract.ts`) and refuses, never repairs, what does not match.

## Common rules

- Base: `https://<api>/api/v1/access/runtime`. HTTPS only; redirects are refused by the client.
- Authentication: the enrolled host Agent identity, exactly as `/dns/runtime/*` and
  `/logs/runtime/*`:
  - `Authorization: Bearer <agent token>`
  - `X-MNSCloud-Agent-UUID: <agent uuid>`
    The API authenticates the Agent (`AgentRuntimeService.authenticate`) and then checks the exact
    binding: Agent -> `AccessGateway` (claimed installation), and for `/connections/:uuid/*` that the
    connection is assigned to that gateway and is in a state that allows the call. Wrong Agent or
    gateway: `403 ACCESS_GATEWAY_AGENT_FORBIDDEN`. Unknown connection or not this gateway's:
    `404 ACCESS_GATEWAY_CONNECTION_NOT_FOUND`.
- Responses: `Cache-Control: no-store`, JSON envelope `{ "status": "success", "message": "...",
  "data": <payload>, "duration": <ms> }`. The gateway reads only `data`.
- Errors: non-2xx with `{ "code": "ACCESS_GATEWAY_<NAME>", "error": "<text>" }`. The gateway shows
  only the HTTP status and the code (never the body).
- Request bodies are JSON (`Content-Type: application/json`) except recording parts.
- Never log request or response bodies of this prefix (wrap tokens, recordings, command lines).
- UUIDs are lowercase canonical (`8-4-4-4-12`). Times are ISO 8601 UTC.
- Pins (SSH host key and API-SSL certificate) use one format: `SHA256:` + unpadded base64 of the
  SHA-256 digest (43 characters), the OpenSSH form already stored in `NwdHostKeyFingerprint`
  (`^SHA256:[A-Za-z0-9+/]{43}$`). For TLS the digest is over the leaf certificate DER.

## 1. Installation (bootstrap)

The App shows the command the API generates (same shape as the DNS/Logs runtimes, built by the
App's `runtimeInstallCommand('access-gateway', apiBase, gatewayUUID, data)`):

```text
sudo install -d -m 0755 /opt/mnscloud && cd /opt/mnscloud && ([ -d mnscloud-access-gateway/.git ] || sudo git clone https://github.com/manaoscloud/mnscloud-access-gateway.git) && sudo git -C mnscloud-access-gateway fetch --tags --force origin && sudo git -C mnscloud-access-gateway checkout --detach '<ref>' && sudo bash /opt/mnscloud/mnscloud-access-gateway/scripts/install-access-gateway.sh --api-base '<api base>' --server-uuid '<AccessGateway UUID>' --installation-token '<64 hex>' && sudo bash /opt/mnscloud/mnscloud-access-gateway/scripts/validate-access-gateway.sh
```

A resumed installation (Retry) omits `--installation-token`. The token reaches the bootstrap only on
stdin. `--server-uuid` is the `AccessGateway` UUID.

Master route that issues it (API work item, not here): `POST /system/access-gateways/:uuid/installation`
returns `{ installationUUID, installationToken (64 hex, shown once), ref, commitSha, ttlMinutes: 30 }`,
stores only the SHA-256 of the token, pins the latest approved `mnscloud-access-gateway` release.

### 1.1 `GET /gateways/:gatewayUUID/installation`

Resume. `data`: the installation material bound to this Agent, or `null` when none.

### 1.2 `POST /gateways/:gatewayUUID/installation-claim`

Request:

```json
{
  "installationToken": "<64 hex>",
  "hostname": "<host name>",
  "address": "<private IPv4/IPv6 of this host>"
}
```

The API checks the token digest, TTL (30 min), that the Agent belongs to an environment of the
issuing platform master, and that `address` is one of the private addresses the Agent reported.
The first claim binds Agent <-> gateway (one-use). Errors: `ACCESS_GATEWAY_INSTALLATION_EXPIRED`,
`ACCESS_GATEWAY_ALREADY_BOUND`, `ACCESS_GATEWAY_ADDRESS_INVALID`, `ACCESS_GATEWAY_AGENT_FORBIDDEN`.

Response `data` (also the shape of 1.1):

```json
{
  "installationUUID": "uuid",
  "state": "installing | operational | failed",
  "ref": "v0.1.0",
  "commitSha": "<40 hex, the approved release commit>",
  "gatewayUUID": "uuid (same as the path)",
  "gatewayKey": "gw-dev1 (^[a-z0-9][a-z0-9-]{1,62}$, used in the public path /access-gateway/<key>/ws)",
  "listenAddress": "<private address of this host the edge reaches>",
  "listenPort": 7443
}
```

### 1.3 `POST /installations/:installationUUID/report`

```json
{
  "state": "operational",
  "observed": {
    "serviceActive": true,
    "version": "0.1.0",
    "hostname": "...",
    "operatingSystem": "debian-13",
    "architecture": "x86_64",
    "listenAddress": "...",
    "listenPort": 7443,
    "listenerCertificateSha256": "<64 hex of the listener certificate DER>",
    "listenerCertificatePem": "-----BEGIN CERTIFICATE-----..."
  }
}
```

or `{ "state": "failed" }`. The certificate is public: nginx pins it for the edge upstream
(`proxy_ssl_trusted_certificate` + `proxy_ssl_verify on`, name = listen IP). `data`: ignored.

## 2. `GET /config`

`data`:

```json
{
  "gatewayUUID": "uuid",
  "gatewayKey": "gw-dev1",
  "environment": "development | production",
  "listen": { "address": "<private address>", "port": 7443 },
  "edgeSources": ["<CIDR of each edge (nginx) host allowed to reach 7443>"],
  "denylist": ["<CIDR>", "..."],
  "labTargets": ["<single-host CIDR>"],
  "sessionNetwork": { "ipv4": "100.127.192.0/18", "ipv6": "fd6d:6e73:6177::/48" },
  "capacity": { "maxSessions": 32 },
  "openvault": { "address": "https://<openvault>:8200", "caCertificatePem": "<PEM or null>" },
  "sandbox": { "memoryMaxMB": 256, "cpuQuotaPercent": 50, "tasksMax": 64 },
  "configDigest": "<opaque, changes whenever any field changes>"
}
```

- `denylist`: platform ranges the public path must never reach: DEV/PROD networks, management VPN
  ranges, MNSCloud public blocks. The gateway always adds the built-in special ranges
  (`src/controller/denylist.ts`: RFC 1918, RFC 6598, loopback, link-local incl. 169.254.169.254,
  multicast, documentation, NAT64, 6to4, Teredo, ULA, ...).
- `labTargets`: the DEV-only `ACCESS_GATEWAY_LAB_TARGETS` (/32 or /128 only). The API sends it only
  when `environment` is `development`; the gateway ignores it otherwise.
- `edgeSources` empty means the listener accepts nobody (fail-closed).
- `sessionNetwork`, `capacity`, `sandbox` are optional (defaults shown).

## 3. `GET /assignments?cursor=<opaque>&wait=<seconds>&free=<slots>`

Long poll (the API holds the request up to `wait` seconds, max 25, and answers at once when there is
something). Returns at most `free` new assignments for this gateway and marks them delivered;
repeating a cursor re-delivers what was not acknowledged by a later poll.

`data`:

```json
{ "cursor": "<opaque, <=256 chars>", "assignments": [ <Assignment> ], "cancelled": ["<connectionUUID>"],
  "attachTickets": [ { "connectionUUID": "uuid", "sha256": "<64 hex>", "expiresAt": "ISO", "role": "operator | observer" } ] }
```

`attachTickets` (optional, absent = none): extra single-use tickets for a browser to attach to a
connection that is already live on this gateway (support sessions, section 12). `sha256` is the hex
SHA-256 of the ASCII ticket, like `ticket.sha256`; the gateway keeps one only for a live connection of
its own (duplicates by hash are ignored, an expired one is dropped silently) and accepts it once, until
`min(expiresAt, received + 60 s)`. Invalid items are skipped.

`cancelled`: connections the user closed (tenant `DELETE` connection) or the API revoked; the gateway
ends them (finish reason `cancelled`).

### Assignment

```json
{
  "connectionUUID": "uuid",
  "mode": "console | test | exec",
  "protocol": "ssh | routeros_api",
  "path": "public | connector | mgmt_vpn",
  "transport": "direct | connector | mgmt_vpn",
  "mgmtVpn": "{ \"hubUUID\": \"uuid\", \"source\": \"<IPv4 literal>\" } (required, and only allowed, when transport is mgmt_vpn)",
  "connectorUuid": "uuid (required, and only allowed, when transport is connector)",
  "connectorKeyFingerprint": "SHA256:<44 base64 chars incl. padding> (required with transport connector)",
  "target": { "address": "<IP literal resolved by the API with the rebinding guard>", "port": 22 },
  "shellDialect": "routeros | linux | proxmox | vrp | other",
  "username": "<device login, no CR/LF/NUL, <=128>",
  "level": "n1 | n2 | n3",
  "hostKey": { "pinned": "SHA256:... | null" },
  "tls": { "pinned": "SHA256:... | null" },
  "ticket": { "sha256": "<64 hex>", "expiresAt": "ISO" },
  "detachable": false,
  "exec": "(required, and only allowed, when mode is exec; section 13)",
  "terminal": { "cols": 120, "rows": 32 },
  "limits": {
    "maxSessionSeconds": 14400,
    "idleSeconds": 900,
    "maxOutputBytesPerSecond": 262144,
    "maxOutputBytes": 268435456
  },
  "recording": { "enabled": true, "partBytes": 1048576, "partSeconds": 60 }
}
```

- `ticket` is required for `console` and `null` for `test` ("Testar acesso": the gateway connects at
  once, verifies the key/certificate, logs in, reads facts and finishes).
- `ticket.sha256` = lowercase hex SHA-256 of the ASCII ticket string the browser receives. The
  ticket is 32 random bytes from the API, base64url without padding (43 characters). The gateway
  accepts it once, until `min(expiresAt, received + 60 s)`.
- `mode: exec` (AI copilot, section 13): no browser, no ticket (`null`), `detachable` is `false`,
  `terminal` is ignored and `recording` is never produced (the outputs travel in the result). It
  needs `protocol: ssh` and the `exec` payload; the gateway connects at once, like `test`.
- `protocol` `routeros_api` is accepted only with `mode: test` and port 8729 semantics (TLS). Port 23
  and 8728, `telnet`, and any `path` other than `public`, `connector` and `mgmt_vpn` are refused in
  this release. `transport` defaults to the path (`direct` for `public`); `path: connector` requires
  `transport: connector` and `path: mgmt_vpn` requires `transport: mgmt_vpn` (and the reverse),
  otherwise `path_unsupported`. Assignments without `mgmtVpn` keep working unchanged.
  `connectorKeyFingerprint` is the fingerprint of the connector public key the API has on file
  (`SHA256:` + base64 of sha256(raw key), as in `AcnPublicKeyFingerprint`); the gateway refuses the
  connection (`refused`, `connector_key_mismatch`) when the tunnel authenticated with another key,
  and drops any tunnel whose key it can no longer confirm with `GET /connectors/:uuid` (checked
  every 60 s: a disabled, deleted or re-installed connector loses its tunnel).
- The gateway refuses (finish `refused`) any target in the denylist unless it is a DEV lab target.
  For `transport: connector` the public denylist does not apply (tenant private ranges are the
  point); the gateway still refuses loopback, link-local, multicast, unspecified, broadcast and
  IPv4-mapped targets and ports 23/8728, and finishes `failed` with `connector_offline` when the
  connector has no tunnel attached to this gateway (see "Remote access connector").
- For `transport: mgmt_vpn` (management VPN, section 11) `target.address` must be an IPv4 literal
  inside the hub's `mgmtNet`; `mgmtVpn.source` is the owner's address (an IPv4 literal; a different
  value per tenant), `mgmtVpn.hubUUID` the hub the API resolved. The public denylist does not apply
  (the range is private on purpose); the host firewall lets only this path use it. Ports 23/8728 are
  refused. The gateway finishes `failed` with `mgmt_vpn_unavailable` when it has no hub, the hub
  differs from `hubUUID`, the destination is outside `mgmtNet`, or `source` is not on the interface
  (after one immediate synchronisation).
- `detachable` (optional, default `false`, honored only for `console`): the connection belongs to a
  support session. When the operator browser closes, the gateway does not end the connection: it
  calls `POST /connections/:uuid/detach` (section 12) and keeps the device connected; the idle and
  maximum duration limits still end it, and a detachable connection with no operator attached for
  `limits.idleSeconds` (reattaching resets it) ends with reason `idle_timeout` (close 4408) even if
  the device keeps producing output. Without it (or `false`) a closed browser finishes the
  connection with `browser_closed`, as before.
- `level` drives the manual-mode policy (`src/worker/policy.ts`).

## 4. `POST /connections/:uuid/hostkey`

Sent before any authentication. Request:

```json
{
  "kind": "ssh | tls",
  "algorithm": "ssh-ed25519 | x509 | ...",
  "fingerprint": "SHA256:...",
  "result": "match | mismatch | unpinned"
}
```

`data`: `{ "decision": "accept | block", "pinned": true | false }`.

- `match`: informative (the gateway continues). `mismatch`: the gateway always blocks; the API
  records it (cleared in Rede through the existing host-key DELETE).
- `unpinned`: the API pins it (`ProcNetworkDeviceHostKeyPin` for `ssh`, the new `NweTls*` procedure
  for `tls`) as the session user only when that user has `tenant.network.devices.hostkey`, and
  answers `{ decision: "accept", pinned: true }`; otherwise `{ decision: "block", pinned: false }`.
  The gateway continues only on `accept` + `pinned`.

## 5. Credential pull

### 5.1 `POST /connections/:uuid/credential`

Called only after the host key was accepted and the worker reached authentication. Request:
`{ "workerReady": true }`. The API calls
`issueConnectionCredential({ purpose: 'gateway', sessionUUID, gatewayAgentUUID, ttlSeconds: 30 })`
only when the connection is assigned to this gateway and in the authenticating state (once per
connection attempt). `data`:

```json
{ "credentialUseUUID": "uuid", "wrapToken": "<OpenBao response-wrapping token>", "ttlSeconds": 30 }
```

The gateway unwraps it at `<openvault.address>/v1/sys/wrapping/unwrap` (header `X-Vault-Token`). The
unwrapped secret (`data`, or `data.data` for KV v2) holds `username` (optional; else the assignment
username) and `password` and/or `privateKey` (`private_key` accepted) and optional `passphrase`.

### 5.2 `POST /connections/:uuid/credential/result`

`{ "credentialUseUUID": "uuid", "result": "used | auth_failed | unwrap_failed | unused" }` ->
`finishConnectionCredentialUse`. `data`: ignored.

## 6. `POST /connections/:uuid/events`

Batched (every second or 50 events), in order. Request `{ "events": [ <Event> ] }`, `seq` increases
per connection from 1. Event shapes:

```json
{ "seq": 1, "at": "ISO", "type": "state", "state": "starting | connecting | hostkey_check | authenticating | ready | closed | failed | refused | expired", "reason": "<code, optional>" }
{ "seq": 2, "at": "ISO", "type": "hostkey", "kind": "ssh | tls", "fingerprint": "SHA256:...", "result": "match | mismatch | unpinned", "decision": "accept | block" }
{ "seq": 3, "at": "ISO", "type": "credential", "result": "delivered | unavailable" }
{ "seq": 4, "at": "ISO", "type": "command", "line": "<redacted reconstructed line>", "class": "read | write_low | write_risky | destructive | pivot | secret_read", "unknown": false, "verdict": "allowed | confirmed | denied | blocked | expired", "level": "n2", "rule": "<rule id or null>" }
{ "seq": 5, "at": "ISO", "type": "notice", "code": "output_throttled", "message": "..." }
```

`AccessGatewayConnectionEvent` stores `command` events (line, class, verdict; "confirmed by" is the
connection user). `data`: ignored.

## 7. `PUT /connections/:uuid/recording/parts/:n`

Body: raw bytes, `Content-Type: application/x-asciicast`, header `X-MNSCloud-Part-SHA256: <hex>`.
`n` starts at 0; parts arrive in order; part 0 begins with the asciicast v2 header line. Each part is
a whole number of asciicast lines (redacted output `o`, resize `r`, markers `m`; keystrokes are
never recorded). The API writes them to Storage (`docs/storage-file-contract.md`, 90-day retention)
and rejects a part whose SHA-256 does not match (`ACCESS_GATEWAY_PART_DIGEST`) or arrives out of
order (`ACCESS_GATEWAY_PART_ORDER`). Max part 8 MB. `data`: ignored.

## 8. `POST /connections/:uuid/finish`

Exactly once per connection (also for refused and expired assignments).

```json
{
  "state": "closed | failed | refused | expired",
  "reason": "device_closed | browser_closed | idle_timeout | max_duration | output_limit | cancelled | gateway_shutdown | gateway_full | test_ok | exec_done | exec_payload_mismatch | exec_change_unsupported_transport | hostkey_mismatch | hostkey_rejected | auth_failed | credential_unavailable | connect_failed | tls_failed | protocol_error | protocol_refused | destination_refused | invalid_assignment | path_unsupported | connector_offline | mgmt_vpn_unavailable | connector_key_mismatch | connector_open_failed | not_allowed | api_refused | api_unavailable | connect_timeout | open_timeout | too_many_streams | tunnel_closed | ticket_expired | sandbox_failed | shell_refused | device_error | worker_failed",
  "bytesFromDevice": 0,
  "bytesToDevice": 0,
  "durationMs": 0,
  "recording": {
    "parts": 3,
    "bytes": 1234,
    "sha256": "<hex SHA-256 of the newline-joined hex SHA-256 of each part, in order>"
  },
  "facts": {
    "identity": "RB-Lab",
    "version": "7.24.6 (stable)",
    "boardName": "CHR",
    "architecture": "x86_64",
    "uptime": "1d2h",
    "cpuLoad": "3",
    "freeMemory": "...",
    "totalMemory": "..."
  }
}
```

`recording` and `facts` may be `null`. `facts` comes from "Testar acesso" (RouterOS API-SSL
`/system/identity/print` and `/system/resource/print`; SSH test only proves login). `data`: ignored.

## 12. Attach and detach (support sessions)

### `POST /connections/:uuid/attach`

Sent by the gateway when a browser presents an attach ticket (`attachTickets`, section 3) before the
WebSocket upgrade. Request: `{ "sha256": "<64 hex of the presented ticket>" }`. The API consumes the
ticket for that connection (single use) and answers `data: { "role": "operator | observer" }`. Any
error (4xx/5xx, network, invalid `role`) makes the gateway answer the browser `401` without
upgrading; the ticket stays spent.

### `POST /connections/:uuid/detach`

Request `{}`. Sent best effort (failures are only logged) when the operator browser of a
`detachable` connection closed or errored. Audit only: the connection stays live.

## 13. Exec mode and `POST /connections/:uuid/exec-result` (AI copilot)

`mode: exec` runs a fixed list of commands on one device for the remote support AI copilot (reads
the AI asked for, or a change the technician approved) and returns the redacted outputs. The
gateway never invents or edits a command: it classifies the list, runs it or refuses it.

### `exec` payload

```json
{
  "kind": "read | change",
  "requestUUID": "<the connectionUUID: 32 hex or the dashed form, any case>",
  "steps": ["1..30 commands, each <= 1000 chars, no CR/LF/NUL"],
  "verify": ["change only: 1..10 read commands, run in a NEW SSH session"],
  "rollback": ["change + systemd_deadman only: 1..30 commands"],
  "safeChange": "routeros_safe_mode | vrp5_schedule_reboot | systemd_deadman | none",
  "rollbackSeconds": 300,
  "backupName": "^[a-z0-9-]{1,48}$ (change only, else null)",
  "changeLog": {
    "kind": "script | file | report_only",
    "line": "<=300 printable ASCII, no quotes, backslash, $, backtick or ;"
  },
  "sha256": "<hex sha256 of the canonical JSON>"
}
```

- Validation is strict (unknown keys, wrong types, bounds are refused, never corrected). `read`
  needs `safeChange: none`, empty `verify`/`rollback`, `backupName` and `changeLog` `null`. `change`
  needs `rollbackSeconds` 120..900, `verify`, a `backupName`, and a `safeChange` that matches the
  dialect: `routeros_safe_mode` (routeros, `changeLog` script or report_only),
  `vrp5_schedule_reboot` (vrp, report_only), `systemd_deadman` (linux/proxmox, `rollback` required,
  `changeLog` file or report_only). `none` is refused for a change. The dialect `other` is
  refused for exec (read and change). Commands may not contain control characters (Tab included,
  `\x00-\x1f`, `\x7f`), and not `?` on routeros and vrp (inline help). A change also needs
  `steps.length * 30 + 60 <= rollbackSeconds` (every step may take 30 s and the rollback must still
  be armed when the last one ends). `rollbackSeconds` is 0..900 for
  a read (it is part of the hash).
- `sha256` = hex SHA-256 of `JSON.stringify({kind, steps, verify, rollback, safeChange,
  rollbackSeconds, backupName, changeLog})` (that key order; `changeLog` is `{kind, line}` or
  `null`). The gateway recomputes it in the controller and again in the worker. A mismatch (or any
  invalid payload) is refused before anything runs: `POST /exec-result` with status `failed` and
  `error.code` `EXEC_PAYLOAD_MISMATCH` (`EXEC_INVALID_ASSIGNMENT` otherwise), then `finish`
  `refused` with reason `exec_payload_mismatch` (`invalid_assignment`).
- A `change` over `transport: connector` is refused (`finish` `refused`,
  `exec_change_unsupported_transport`): the verification needs a second SSH connection and the
  connector bridge carries one stream.

### Policy (before anything runs)

Every `steps`, `verify` and `rollback` command is classified by the dialect rules
(`Classifier(loadRules(dialect))`, `level` of the assignment). Any blocked command makes the whole
request `blocked`: nothing connects, no credential is pulled.

- `read`: every step must be class `read` and known (`unknown=false`) and pass the exec-read
  policy, stricter than the console because no human reviews the line:
  RouterOS needs an absolute path ending in a full read verb (`print`, `export` without `file=`,
  `monitor` with `once` or `duration=`, `get`, `ping` with `count=`, `traceroute`) or a plain
  `:put`/`:len`-style read; navigation (and abbreviations that classify as navigation), `[`, `;`,
  `{`, `}`, `$`, `follow` and `interval=` are refused. Linux/Proxmox refuse glob and expansion
  characters (`*?[]{}~`), `cd`, secret paths (shadow, gshadow, `id_*`, `ssh_host_*_key`, `*.key`,
  `private`) and flags that write or act (`sort -o`, `uniq` with two files, `tree -o`, `xxd -r`,
  `sar -o`, `dmesg -c/-C/--clear`, `ss -K`, `man -P/-H`, `yq -i`, `arping -U/-A`, `ping -f`,
  `localectl|loginctl|resolvectl|timedatectl|hostnamectl` with a verb other than
  `status|list*|show*`). VRP accepts `display`, `ping` and `tracert` only, without redirection.
- `change`: a step or rollback command runs only when `decide(level, class)` is `allow` or
  `confirm` (the technician approved it in the API); `double_confirm` and `block` are blocked,
  `destructive` / `secret_read` are always blocked, and an `unknown` command is blocked. `verify`
  must be `read`, known and pass the exec-read policy. No step or rollback command may disarm the
  rollback: VRP `save`/`sa`, `schedule`/`undo schedule`, `startup`, `commit`, `reboot`, `quit`
  (prefix abbreviations included); Linux anything naming `mns-rb-`, `systemctl stop|disable|mask|kill`
  of timers, `systemd-run`, `at`, `batch`, `nohup`, `setsid`, `disown`, `crontab`, a trailing `&`,
  `reboot|shutdown|poweroff|halt`; RouterOS only absolute commands and none of `:execute`,
  `/import`, `/quit`, `/system script run`, `/system scheduler`, `/system reboot|shutdown`,
  `/tool netwatch` (word prefixes such as `/sys sched` included) or rule `ros-script-exec`.
- Commands run one per exec channel start at the root menu (RouterOS), so they are classified one
  by one; a shell session (RouterOS safe mode, VRP) keeps the menu between commands.

### Execution

Per command: timeout 20 s (steps of a change 30 s), output cap 64 KiB (head kept, `truncated`,
last partial line dropped), ANSI stripped, then redacted (dialect patterns plus the credential
password/passphrase/key as literals). Raw output is never logged.

- `read` routeros/linux/proxmox: one SSH connection, one exec channel per command, exit code
  (`null` when the device sends none). `read` vrp/other: shell with prompt detection (VRP
  `screen-length 0 temporary` first, output ignored); a command that does not return to the prompt
  ends the request `failed` (`COMMAND_TIMEOUT`).
- `change` `routeros_safe_mode`: login `<user>+ct4096w` on a 4096-column PTY (no colors, no
  terminal detection); the `-- [Q quit|D dump|down]` pager is answered `D`, and a lone CR starts a
  new line for prompt detection. `/export file=<backupName>`, Ctrl-X
  (safe mode), each step (fails on the RouterOS error patterns), verification in a NEW SSH
  connection (same worker, same in-memory credential, same host key), Ctrl-X again (commit), the
  change log script lines, `/export file=pos-<name>`, `/quit`. Any failure before the commit drops
  the socket without logout (RouterOS reverts safe mode): `rolled_back`. A Ctrl-X release whose
  prompt does not come back in 10 s is `failed` / `RELEASE_UNCERTAIN` (socket dropped, state to be
  checked). After the commit nothing turns the result into a failure: a later error (change log,
  export, connection lost, abort) leaves `applied` with `CHANGELOG_FAILED`, `EXPORT_FAILED` or
  `EXEC_ABORTED`.
- `change` `vrp5_schedule_reboot`: `save <backupName>.cfg`, `schedule reboot delay 00:<mm>`
  (both answered `Y`), `system-view`, steps, `return`, verification in a NEW session, then
  `undo schedule reboot` and `save` (`Y`). A `[Y/N]` question during a step is answered `N` and
  fails the request. On failure nothing is saved and the device reboots into the saved
  configuration: `rolled_back` with `rollback.pendingReboot: true`. The scheduled reboot reverts
  the device to its startup (saved) configuration, so any other unsaved running change is lost
  too; on success `save` stores the whole running configuration, including changes that were
  pending before the request.
- `change` `systemd_deadman`: `id -u` (non-root: system, AI and verify commands run as
  `sudo -n /bin/sh -c '<command>'`), `systemd-run --unit=mns-rb-<32 hex of requestUUID>
  --on-active=<rollbackSeconds> --timer-property=AccuracySec=1s --property=Type=oneshot
  --property=TimeoutStartSec=120 /bin/sh -c 'echo <base64 of rollback> | base64 -d | /bin/sh'`
  (exit != 0: `failed`, nothing applied), steps, verification in a NEW connection, then
  `systemctl stop mns-rb-<id>.timer` and the change log line. A failing step or verification runs
  `systemctl start mns-rb-<id>.service` and stops the timer: `rolled_back`; when that start exits
  non-zero the timer is NOT stopped and the result is `failed` / `ROLLBACK_FAILED` with
  `rollback.armed: true`. Linux verification needs exit code 0 (RouterOS accepts no exit status).
- Time budget: before each step and before the commit, if more than `rollbackSeconds - 30 s` have
  passed since the rollback was armed, the request rolls back (`DEADLINE`) instead of committing.
- The finish reason is always `exec_done` (state `closed`) once a result exists, also for
  `blocked`, `failed` and `rolled_back`; host key, authentication and connection failures keep
  their usual reasons (`hostkey_mismatch`, `auth_failed`, `connect_failed`, ...) and also carry
  an `exec-result` with the matching `error.code`.

### `POST /connections/:uuid/exec-result`

Sent once per exec connection by the controller (Agent identity, like `/events`), before
`/finish`. A network or 5xx failure is retried with backoff (1, 3, 8, 20, 30 s); a 4xx other than
408/425/429 is not retried, so the API must treat a repeated identical result as a no-op.

```json
{
  "status": "ok | blocked | failed | applied | rolled_back",
  "steps": [
    {
      "phase": "system | step | verify | rollback",
      "command": "<redacted>",
      "class": "read | write_low | write_risky | destructive | pivot | secret_read | null",
      "rule": "<rule id> | null",
      "verdict": "allowed | blocked",
      "exitCode": 0,
      "output": "<redacted, <= 64 KiB>",
      "truncated": false,
      "ms": 120
    }
  ],
  "rollback": {
    "method": "safe_mode | scheduled_reboot | deadman_timer | none",
    "armed": true,
    "fired": false,
    "pendingReboot": false
  },
  "error": { "code": "STEP_FAILED", "message": "<fixed text, no device output>" }
}
```

- `ok`: a read finished (individual exit codes may be non-zero; a command that timed out has exit
  code 124). `applied`: the change was verified and committed (`error` may carry
  `CHANGELOG_FAILED` / `EXPORT_FAILED` when only the documentation failed). `rolled_back`: the
  vendor rollback ran or is pending (`error.code` `STEP_FAILED`, `VERIFY_FAILED`,
  `RELEASE_FAILED`, `CANCEL_FAILED`, `EXEC_ABORTED`, `CONNECTION_LOST`, `DEADLINE`). `failed`: nothing was
  committed or the state needs attention (`BACKUP_FAILED`, `SAFE_MODE_UNAVAILABLE`,
  `SCHEDULE_FAILED`, `ARM_FAILED`, `IDENTITY_UNKNOWN`, `SAVE_FAILED`, `DEADMAN_DISARM_FAILED`
  (the timer may still revert the change), `ROLLBACK_FAILED`, `RELEASE_UNCERTAIN`,
  `EXEC_REFUSED` (preflight or `gateway_full`; the result is posted before the finish, with the same
  retry), `PROMPT_TIMEOUT`, `COMMAND_TIMEOUT`, `AUTH_FAILED`,
  `HOSTKEY_MISMATCH`, `HOSTKEY_REJECTED`, `CREDENTIAL_UNAVAILABLE`, `CONNECT_FAILED`,
  `EXEC_NO_RESULT`, `EXEC_INTERNAL`). `blocked`: `error.code` `EXEC_BLOCKED`, every step carries
  its class/rule/verdict, `output` empty.
- `system` steps are the gateway's own commands (backup, safe mode, `id -u`, arming, change log);
  their `class` is `null`. The AI `rollback` commands are executed by the device (timer script),
  so only the commands the gateway runs to fire the rollback appear in phase `rollback`.
- The body stays below 1 MiB: when the sum of the outputs would exceed it, the largest outputs
  are halved (`truncated: true`) until it fits.

## 9. `POST /heartbeat`

Every 30 s:

```json
{
  "version": "0.1.0",
  "configDigest": "...",
  "activeSessions": 1,
  "freeSlots": 31,
  "sessions": ["<connectionUUID>"],
  "listenerCertificateSha256": "<hex>",
  "listenerCertificatePem": "-----BEGIN CERTIFICATE-----...",
  "uptimeSeconds": 120
}
```

`data`: `{ "configDigest": "...", "drain": false }`. A different digest makes the gateway reload
`/config` (host firewall and limits are applied at once; a changed listener restarts the
controller). `drain` is informative (the API stops assigning).

## 10. Connector routes of the gateway (host Agent identity, same router)

Used by the connector tunnel (section "Remote access connector"). Base `/api/v1/access/runtime`.

- `GET /connectors/:connectorUuid`: `data` `{ "connectorUuid": "uuid", "publicKey": "<base64url Ed25519, 43 chars>" }`
  for a connector that is `active` + `operational` and belongs to this gateway's environment. Any
  other state (disabled, deleted, awaiting installation, other environment): `403
  ACCESS_GATEWAY_CONNECTOR_FORBIDDEN` or `404 ACCESS_GATEWAY_CONNECTOR_NOT_FOUND` (the gateway treats
  both as an authentication failure of the tunnel).
- `POST /connectors/:connectorUuid/attach` (body `{}`): the authenticated tunnel is now attached to
  this gateway (stores gateway and `AcnTunnelConnectedAt`). A newer tunnel simply overwrites it.
- `POST /connectors/:connectorUuid/detach` (body `{}`): the tunnel closed; clear the attachment only
  when it still points to this gateway.

## 11. Management VPN routes (host Agent identity, same router)

Base `/api/v1/access/runtime`. The gateway polls the first route at start and every 60 s (and when a
`mgmt_vpn` assignment names a source that is not on the interface yet).

- `GET /mgmt-vpn`: `data` is `{ "hub": null }` (no hub bound to this gateway: the gateway deletes its
  interface) or

  ```json
  {
    "hub": {
      "uuid": "uuid",
      "endpoint": "host:port",
      "publicKey": "<44 chars base64 WireGuard key>",
      "mgmtNet": "<IPv4 CIDR, prefix 8..30>",
      "gatewayNet": "<IPv4 CIDR inside mgmtNet>"
    },
    "sources": ["<IPv4 inside gatewayNet>", "..."]
  }
  ```

  An older API answering `404` means "no hub". Anything malformed is ignored (the interface stays as
  it is) and logged.
- `POST /mgmt-vpn/key` body `{ "publicKey": "<44 chars base64>" }`: the gateway's WireGuard public
  key, sent once per process start and after a key change (idempotent). The private key is generated
  on the host (`wg genkey`, `/var/lib/mnscloud/access-gateway/mgmt-vpn.key`, 0600) and never leaves it.

## WebSocket (browser <-> edge <-> gateway)

`wss://<app domain>/access-gateway/<gatewayKey>/ws?ticket=<ticket>` (nginx; it must not log the
query string) -> `https://<listen address>:7443/access-gateway/<gatewayKey>/ws?ticket=...` (TLS with
the pinned listener certificate). The tenant route `POST /network/devices/:uuid/console` returns
`{ connectionUUID, relayUrl, ticket, expiresAt }`. The listener answers only `edgeSources` (host
nftables and the controller both check). Text frames only:

| Direction          | Frame              | Meaning                                                                          |
| ------------------ | ------------------ | -------------------------------------------------------------------------------- |
| gateway -> browser | `OK`               | terminal ready (shell open)                                                      |
| gateway -> browser | `0:<len>:<data>`   | device output, already sanitized and redacted; `len` = UTF-8 bytes of `data`     |
| gateway -> browser | `3:<json>`         | control (below)                                                                  |
| browser -> gateway | `0:<len>:<data>`   | keystrokes (len = UTF-8 bytes; the UTF-16 length is tolerated)                   |
| browser -> gateway | `1:<cols>:<rows>:` | resize                                                                           |
| browser -> gateway | `2`                | ping                                                                             |
| browser -> gateway | `4:<json>`         | `{"type":"confirm","id":"<verdict id>","step":1}` / `{"type":"deny","id":"..."}` |

Device output is always a `0:` frame, unlike the VPS console where output is raw: the App must
parse `0:` for output so device text can never be read as `3:` control.

Attach tickets (support sessions): the same URL with `ticket=<attach ticket>`. The gateway finds it
in its attach book, calls `POST /connections/:uuid/attach` (section 12) and upgrades with the role
the API returned (it must equal the role of the ticket, else `401`). Attach tickets are kept and
honored only for `detachable` connections. On attach the browser first receives the last `state`
control, then `OK` (when the shell is ready), then the last 256 KB of redacted output as `0:` frames
(kept only for detachable connections), then, for an `operator` only, the last `hostkey` control and
a still pending `verdict`; then live frames.

- `operator`: the single input browser. A previous operator socket is closed with code **4410**,
  reason `replaced`, and its close does not detach or end the session.
- `observer`: at most 4 per connection (more get `401`, or close 4429); receives output, `OK` and `state`/`notice` controls only (never verdicts or command
  lines); every input, resize and confirm frame is ignored and its close never ends the session.

Control messages (`3:`):

```json
{ "type": "state", "state": "connecting | hostkey_check | authenticating | ready | closed | failed", "reason": "<code>" }
{ "type": "hostkey", "kind": "ssh | tls", "result": "match | pinned | mismatch | rejected", "algorithm": "...", "fingerprint": "SHA256:..." }
{ "type": "verdict", "id": "v1-ab12cd34", "line": "<redacted line>", "class": "write_low", "unknown": false, "requires": "confirm | double_confirm", "step": 1, "expiresInSeconds": 120 }
{ "type": "blocked", "id": "...", "line": "...", "class": "secret_read", "unknown": false, "hint": "..." }
{ "type": "resolved", "id": "...", "decision": "confirmed | denied | expired" }
{ "type": "notice", "code": "output_throttled", "message": "..." }
```

`double_confirm` sends a second `verdict` with `step: 2` after the first confirmation; each confirm
must carry the current `step`. Close codes: 4401 credential refused/unavailable, 4403 host key not
accepted, 4408 idle/maximum duration, 4409 host key changed, 4410 operator replaced by a new attach, 4413 output limit, 4500 other failure,
1000 normal; HTTP 401 before upgrade for an invalid, used or expired ticket.

## Remote access connector (tenant network path)

A connector is a runtime the tenant installs in its own network (Debian 12/13, Ubuntu 22.04/24.04,
amd64/arm64). It opens an outbound tunnel to the access gateway the platform assigned to it, so the
gateway can reach LAN and CGNAT devices (private addresses). It holds no platform secret: its
identity is an Ed25519 key generated on the tenant host; only the public key is known to the platform.

### Installation

The App shows one command (single-use token, 24 h). The script is downloaded to a private temporary
file and pinned by the SHA-256 the API computes from the raw file of the release tag
(`scripts/install-connector.sh` at `<tag>`); the commit is verified again after the clone. The token
travels on **stdin** (never in the environment or on a command line, where it would show up in
`/proc`, shell history and sudo logs):

```text
f=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/manaoscloud/mnscloud-access-gateway/<tag>/scripts/install-connector.sh -o "$f" \
  && echo "<sha256 of the script at <tag>>  $f" | sha256sum -c - \
  && printf '%s' '<token>' | sudo env MNSCLOUD_API_URL=<public api base> MNSCLOUD_CONNECTOR_RELEASE=<tag> MNSCLOUD_CONNECTOR_COMMIT=<40 hex> bash "$f"; rm -f "$f"
```

- Token: `^[A-Za-z0-9_-]{32,128}$` (the API issues 32 random bytes, base64url, 43 chars). The script
  refuses a token in the environment; with nothing on stdin and a terminal available it prompts
  (`read -rs`). It passes the token to the claim on stdin only.
- `MNSCLOUD_API_URL`: `https://<host>[:port][/api[/v1]]`; the connector normalizes it to `.../api/v1`.
- `MNSCLOUD_CONNECTOR_RELEASE`: `vX.Y.Z` tag of this repository; `MNSCLOUD_CONNECTOR_COMMIT`: the
  commit the tag must resolve to (the script refuses a mismatch). The same two values come back as
  `release` in the config for updates; the updater also refuses a tag older than the running
  `VERSION`.
- The script installs Deno from `mnscloud-runtime-kit` (same pin as the gateway), clones this
  repository to `/opt/mnscloud-access-connector`, creates the system user `mns-connector`, generates
  the key (`/etc/mnscloud-access-connector/key.pkcs8`, 0600, owner `mns-connector`), claims, writes
  `/etc/mnscloud-access-connector/connector.json` (API URL, connector UUID, key path; no secret) and
  installs `mnscloud-access-connector.service` (unprivileged) plus
  `mnscloud-access-connector-update.timer` (root oneshot `scripts/update-connector.sh`).
  `scripts/uninstall-connector.sh` removes everything (the connector must also be deleted in the App).

### `POST /access/connector/claim` (unsigned, token only)

Request `{ "token": "<install token>", "publicKey": "<base64url raw Ed25519, 43 chars>",
"host": "<hostname>", "version": "<VERSION>" }`; response `data` `{ "connectorUuid": "uuid" }`. The
API checks the SHA-256 of the token (single use, 24 h), stores the key and fingerprint, marks the
connector `operational`. Any non-2xx aborts the installation.

### Signed requests (every other connector route)

Base `https://<api>/api/v1/access/connector`. Headers:

| Header            | Value                                                                    |
| ----------------- | ------------------------------------------------------------------------ |
| `X-MNS-Connector` | connector UUID                                                           |
| `X-MNS-Timestamp` | unix seconds (the API accepts +-60 s)                                    |
| `X-MNS-Nonce`     | 24 url-safe characters (the API accepts 16-64), single use per connector |
| `X-MNS-Signature` | base64url (no padding) Ed25519 signature of the string below             |

```text
"mns-connector-v1\n" + METHOD + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + hex(sha256(body))
```

`METHOD` upper case; `path` is the URL path exactly as sent **including `/api/v1`** and without the
query string (the connector sends none); `timestamp` the decimal header value; `body` the raw request
bytes (empty for `GET`, the JSON bytes for `POST`; its sha256 is lower-case hex). Test vector (the
fixed Ed25519 seed is the 32 bytes `00 01 02 ... 1f`; Ed25519 is deterministic):

```text
public key (base64url): A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg
fingerprint:            SHA256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw=
method:                 POST
path:                   /api/v1/access/connector/heartbeat
timestamp:              1767225600
nonce:                  AAAAAAAAAAAAAAAAAAAAAAAA
body:                   {"version":"0.1.4","host":"conn-test","addresses":["10.20.30.40"],"tunnelState":"connected"}
sha256(body):           a5ffc9889f114dd83583f045a6d268af73c983100eafa6b1f29fdfda49110e7e
signed string:          "mns-connector-v1\nPOST\n/api/v1/access/connector/heartbeat\n1767225600\nAAAAAAAAAAAAAAAAAAAAAAAA\na5ffc9889f114dd83583f045a6d268af73c983100eafa6b1f29fdfda49110e7e"
signature (base64url):  r3m4OzeEPpN_UgmO7F8E2eogxE-1__t_3iba29og8UxgDOYPohtnZpqPc_ihHmUpK7o2CuEWIZuvVXKGZwSyCQ
```

The same vector is asserted by `tests/connector_auth_test.ts`. Errors: non-2xx (the connector acts
only on the status): `403` disabled/deleted/unknown connector or bad signature/skew/nonce reuse.

- `POST /heartbeat` every 30 s: `{ "version", "host", "addresses": ["<IP>", ... max 16, informational],
  "tunnelState": "connected | disconnected" }`. `data` ignored.
- `GET /config` every 60 s: `data`

```json
{
  "allowedCidrs": ["10.20.0.0/16"],
  "gateway": {
    "key": "gw-dev1",
    "relayUrl": "wss://<public host>/access-gateway/gw-dev1/connector"
  },
  "release": { "tag": "v0.1.4", "commit": "<40 hex>" }
}
```

`allowedCidrs` (max 64, may be empty/absent), `gateway` (`null` when none is assigned; instead of
`relayUrl` the API may send `relayPath` `/access-gateway/<key>/connector`, resolved against the
API origin) and `release` (`null` when the platform asks for no update) are validated; a response
that does not match is ignored and the previous configuration kept. The relay URL must be `wss`,
without credentials or query, and its path exactly `/access-gateway/<key>/connector`.

- `POST /connections/:connectionUuid/accept`: `{ "destination": "<IP>", "port": 22 }`. `2xx` only
  when this exact connection belongs to this connector (destination and port equal, state
  assigned/connecting, not accepted before, not expired); the API stores the acceptance (single
  use). Any non-2xx is a refusal: the connector never dials.

### Tunnel (`wss://<host>/access-gateway/<gatewayKey>/connector`)

Same edge hosts and listener rules as `/ws` (the edge adds a location next to `/ws` with the pinned
upstream, WebSocket upgrade and a read timeout above 75 s). Text handshake, then binary frames:

1. gateway -> connector: `{"t":"challenge","challenge":"<32 random bytes, base64url, 43 chars>"}`.
2. connector -> gateway: `{"t":"hello","connectorUuid":"<uuid>","signature":"<base64url>"}` where the
   signature covers `"mns-connector-tunnel-v1\n" + gatewayKey + "\n" + challenge` (the connector uses
   the key of the gateway it meant to reach, from its config). Vector with the same key: gatewayKey
   `gw-dev1`, challenge `bm9uY2Utbm9uY2Utbm9uY2Utbm9uY2Utbm9uY2UtMTI`, signature
   `2kJt7jDaV6-w8EzMom7VZhtkezpjEZyGNlaonk091NrmAGBdbqEZJGD41GAHWbsMSX7DY2I_8P7oWXle0vhKAw`.
3. gateway: `GET /access/runtime/connectors/:uuid` (section 10), verifies, `POST .../attach`, answers
   `{"t":"ready","maxStreams":<capacity>,"window":262144}`. Close codes: 4401 not authenticated, 4400
   protocol violation, 4408 handshake timeout (3 s), 4429 busy (per-source and global handshake caps; the source is `X-Real-IP` / the last `X-Forwarded-For` entry set by the edge), 4409 replaced by a newer tunnel, 4503 attach
   refused or gateway shutdown. One tunnel per connector; a newly authenticated one replaces the old.
   The gateway calls `detach` when its tunnel closes (not when it was replaced).

Binary frames: `[type u8][stream u32 big endian][payload]`, whole frame <= 65536 bytes.

| Type | Name      | From      | Payload                                                         |
| ---- | --------- | --------- | --------------------------------------------------------------- |
| 1    | OPEN      | gateway   | JSON `{"connectionUuid","host","port"}` (host is an IP literal) |
| 2    | OPEN_OK   | connector | empty                                                           |
| 3    | OPEN_FAIL | connector | JSON `{"code"}`                                                 |
| 4    | DATA      | both      | bytes, <= 32 KiB per frame                                      |
| 5    | CLOSE     | both      | empty                                                           |
| 6    | CREDIT    | both      | u32 BE bytes the receiver may be sent again                     |
| 7    | PING      | both      | stream 0                                                        |
| 8    | PONG      | both      | stream 0                                                        |

Only the gateway sends OPEN; a connector that does, any unknown type, an oversized frame, DATA beyond
the granted window or credit above 256 KiB ends the tunnel. Every stream starts with a 256 KiB
window per direction; a receiver returns credit as it consumes data. At most `maxStreams` (the
gateway capacity) streams per tunnel (the connector itself allows 64). Idle ping every 20 s (answered with at most one PONG per 2 s); a
tunnel without any frame for 60 s is dead, and one whose socket buffers more than 2 MiB is closed.
Empty DATA frames and more than 256 queued chunks per stream are protocol violations. OPEN_FAIL codes: `destination_refused`, `not_allowed`
(outside `allowedCidrs`), `protocol_refused`, `invalid_address`, `invalid_port`, `invalid_open`,
`api_refused` (4xx from `accept`), `api_unavailable`, `connect_failed`, `connect_timeout` (10 s),
`too_many_streams`.

On OPEN the connector: validates the destination locally (loopback, link-local incl.
169.254.169.254, multicast, unspecified, broadcast and its own addresses are always refused;
`allowedCidrs` narrows; ports 23 and 8728 refused), calls `accept`, dials TCP (10 s) and pipes with
credit flow control. It never executes commands and never listens on a port.

On the gateway the worker of a `transport: connector` connection has no network: systemd
`PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`, and Deno permissions
only for one controller-owned unix socket (`--allow-net=unix:<socket>`); `/run` is an empty tmpfs
in the unit with only that socket bound in under a fixed name, D-Bus and systemd paths are
inaccessible, and the worker must present a per-session secret (sent on its stdin, never argv)
before the controller pipes the socket to the tunnel stream. The stream ends inside the worker's own SSH/TLS client: host key
pinning, redaction, recording and command policy are unchanged. The gateway finishes a connector
connection with `connector_offline` (state `failed`) when no tunnel is attached, or with the OPEN_FAIL
code of the connector (`refused` for the refusal codes, `failed` for the others; any code outside the fixed list is
reported as `connector_open_failed`).
