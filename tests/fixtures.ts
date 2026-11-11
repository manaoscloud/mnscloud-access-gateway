// Shared synthetic test data (documentation addresses, random UUIDs).

export const ASSIGNMENT = {
  connectionUUID: '0b793486-b265-4564-9bfd-df227704d8f9',
  mode: 'console',
  protocol: 'ssh',
  path: 'public',
  target: { address: '203.0.113.10', port: 22 },
  shellDialect: 'routeros',
  username: 'acme-support',
  level: 'n2',
  hostKey: { pinned: null },
  tls: { pinned: null },
  ticket: { sha256: 'a'.repeat(64), expiresAt: new Date(Date.now() + 60000).toISOString() },
  terminal: { cols: 120, rows: 32 },
  limits: {
    maxSessionSeconds: 3600,
    idleSeconds: 900,
    maxOutputBytesPerSecond: 262144,
    maxOutputBytes: 268435456,
  },
  recording: { enabled: true, partBytes: 1048576, partSeconds: 60 },
};
