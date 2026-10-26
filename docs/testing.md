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

Not proved by these tests (deliberate gaps):

- the 2 MiB frame-size limit is only unit-tested in `test/protocol.test.ts`;
  the socket tests do not send oversized frames
- Durable Object eviction/hibernation recovery and reconnect after eviction
- behavior against deployed Cloudflare-hosted workerd rather than the local
  Workers Vitest runtime
- Cloud JWT/JWKS, transport-mode admission and downstream Desktop/Mobile
  integration (outside this repository's scope)

CI **Verify** runs `npm run check` on feature branches and PRs without
Cloudflare deployment; `dev → test → prod` deployment remains unchanged.

This change preserves the existing self-hosted V1 authentication and routing
contract; it does **not** add Cloud JWT validation, Cloud room-role admission,
or evidence from a deployed hosted environment. Those belong to REL-001
implementation/acceptance after this test foundation.
