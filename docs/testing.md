# Tests and module boundaries

Run on Node 22:

```bash
npm install --legacy-peer-deps  # npm 10 peer-tree resolver workaround
npm run check                 # TypeScript + Vitest in workerd
npm run test:watch            # optional during development
```

Repository modules are small by responsibility:

- `src/index.ts`: stable Wrangler entrypoint (re-exports only)
- `src/worker.ts`: HTTP health, routing and Durable Object dispatch
- `src/room.ts`: Durable Object lifecycle and coordination
- `src/room-admission.ts`: existing V1 Host / Client token authentication
- `src/room-forwarding.ts`: request / response and cancellation routing
- `src/room-sockets.ts`: socket selection, cleanup and pending-request release
- `src/room-state.ts`: attachment serialization and safe frame send
- `src/protocol.ts`: bounded frame, room, token and request-ID parsing
- `src/cloud-relay-ticket.ts`: canonical Cloud Relay ticket literals and errors
- `src/cloud-relay-jwks.ts`: bounded trusted Cloud Auth JWKS fetch and cache
- `src/cloud-relay-verifier.ts`: isolated Cloud Relay ticket verification
- `src/cloud-room-admission.ts`: Cloud-only hello admission using verified tickets
- `src/cloud-provenance.ts`: server-authored Client provenance for Host frames

Tests are also independent, intentionally small:

- `test/protocol.test.ts`: malformed frames, paths, tokens and routing IDs
- `test/worker.test.ts`: actual Worker `fetch()` routes in workerd
- `test/admission.test.ts`: legacy Host / Client auth and negative cases
- `test/forwarding.test.ts`: request/complete/cancel and foreign-response isolation
- `test/room-harness.ts`: small real-workerd peer/storage fixture shared by the
  Durable Object WebSocket tests
- `test/room-handshake-socket.test.ts`: Host/Client hello, token-hash
  persistence and rejected peer/frame cases over real WebSockets
- `test/room-forwarding-socket.test.ts`: request/response/complete/cancel,
  client requestId ownership and cross-client isolation over real WebSockets
- `test/room-lifecycle-socket.test.ts`: Host replacement/disconnect and Client
  disconnect active-work cleanup over real WebSockets
- `test/cloud-relay-verifier.test.ts`: Cloud Relay ticket claims, signature,
  header and connection-context rejection with ephemeral Ed25519 keys
- `test/cloud-relay-jwks.test.ts`: trusted JWKS cache bounds, fail-closed
  behavior, key rotation and token-selected-key rejection
- `test/cloud-provenance.test.ts`: Cloud Client provenance authorship, forged
  identity stripping, missing identity fail-closed, multi-client isolation and
  Legacy forwarding compatibility
- `test/cloud-room-socket.test.ts`: real Durable Object Cloud Host/Client
  admission, forwarding with trusted provenance, denial cases and expiry
- `test/cloud-relay-fixtures.ts`: upstream-aligned claim fixtures and ephemeral
  signing helpers

## Durable Object WebSocket evidence

Cloudflare's Workers Vitest integration requires `--max-workers=1 --no-isolate` for
Durable Object WebSocket tests; both `npm test` and `npm run test:watch` use
this supported shared-storage mode. Tests use separate room IDs and await
peer closure in teardown; this does not prove eviction/hibernation recovery.

The `test/room-*-socket.test.ts` files connect through `exports.default.fetch()`
with an `Upgrade: websocket` request, so they exercise the Worker route, the
real `RelayRoom` Durable Object, hibernatable `WebSocketPair` sockets and
SQLite storage in the local Workers runtime. They do not mock the Durable
Object under test. Durable Object state assertions use `runInDurableObject()`
and inspect the real socket attachments and `relay_config` rows.

Covered evidence:

- V1 Host/Client hello, token-hash-only persistence and unauthorized rejection
- request → response → complete and cancel with connection-qualified routing
- stale/foreign responses and cross-client response isolation
- Host replacement, Host disconnect, Client disconnect and active-work cleanup
- Cloud signed Host/Client hello, denial cases and ticket-expiry behaviour
- Cloud Client forwarding with server-authored `relayProvenance`, forged
  identity stripping and per-socket Mobile isolation in real workerd

Not proved by these tests (deliberate gaps):

- the 2 MiB frame-size limit is only unit-tested in `test/protocol.test.ts`;
  the socket tests do not send oversized frames
- Durable Object eviction/hibernation recovery and reconnect after eviction
- behavior against deployed Cloudflare-hosted workerd rather than the local
  Workers Vitest runtime
- real Cloud Auth-issued tickets and downstream Desktop/Mobile integration;
  the locally signed fixtures are not cross-service acceptance evidence

CI **Verify** runs `npm run check` on feature branches and PRs without
Cloudflare deployment; `dev → test → prod` deployment remains unchanged.

The self-hosted V1 authentication and routing contract is preserved. Cloud
admission and provenance are separate from the Legacy token path and provide no
Host business authorization.
