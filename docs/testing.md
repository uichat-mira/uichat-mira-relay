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

CI **Verify** runs `npm run check` on feature branches and PRs without
Cloudflare deployment; `dev → test → prod` deployment remains unchanged.

This PR preserves the existing self-hosted V1 authentication and routing
contract; it does **not** add Cloud JWT validation, Cloud room-role admission,
or full hosted Host/Client WebSocket end-to-end evidence. Those belong to
REL-001 implementation/acceptance after this test foundation.
