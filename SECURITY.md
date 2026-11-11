# Security Policy

This repository is public. Treat all code and documentation as publicly visible.

Report vulnerabilities privately to the maintainers (do not open a public issue or pull request with
exploit details). Include the affected version and reproduction steps with synthetic data only
(documentation addresses such as `192.0.2.0/24`, `2001:db8::/32`).

Areas of special interest:

- escaping the per-session sandbox (network namespace, nftables, systemd properties, Deno
  permissions) or reaching platform networks, cloud metadata or other tenants' devices;
- bypassing the command classifier (a write or destructive command that runs without confirmation,
  an `unknown` line that does not fail closed);
- secrets leaking past redaction into WebSocket frames, recordings or command events;
- host key or certificate pin bypass, ticket reuse or forgery;
- protocol parser bugs reachable from a hostile device (SSH, RouterOS API).

Do not commit tokens, passwords, keys, JWTs, customer data, production addresses or private
topology. Test keys and certificates are generated at test time.
