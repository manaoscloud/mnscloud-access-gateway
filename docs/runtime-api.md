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
{ "cursor": "<opaque, <=256 chars>", "assignments": [ <Assignment> ], "cancelled": ["<connectionUUID>"] }
```

`cancelled`: connections the user closed (tenant `DELETE` connection) or the API revoked; the gateway
ends them (finish reason `cancelled`).

### Assignment

```json
{
  "connectionUUID": "uuid",
  "mode": "console | test",
  "protocol": "ssh | routeros_api",
  "path": "public",
  "target": { "address": "<IP literal resolved by the API with the rebinding guard>", "port": 22 },
  "shellDialect": "routeros | linux | proxmox | vrp | other",
  "username": "<device login, no CR/LF/NUL, <=128>",
  "level": "n1 | n2 | n3",
  "hostKey": { "pinned": "SHA256:... | null" },
  "tls": { "pinned": "SHA256:... | null" },
  "ticket": { "sha256": "<64 hex>", "expiresAt": "ISO" },
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
- `protocol` `routeros_api` is accepted only with `mode: test` and port 8729 semantics (TLS). Port 23
  and 8728, `telnet`, and any `path` other than `public` are refused in this release.
- The gateway refuses (finish `refused`) any target in the denylist unless it is a DEV lab target.
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
  "reason": "device_closed | browser_closed | idle_timeout | max_duration | output_limit | cancelled | gateway_shutdown | gateway_full | test_ok | hostkey_mismatch | hostkey_rejected | auth_failed | credential_unavailable | connect_failed | tls_failed | protocol_error | protocol_refused | destination_refused | invalid_assignment | path_unsupported | ticket_expired | sandbox_failed | shell_refused | device_error | worker_failed",
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
accepted, 4408 idle/maximum duration, 4409 host key changed, 4413 output limit, 4500 other failure,
1000 normal; HTTP 401 before upgrade for an invalid, used or expired ticket.
