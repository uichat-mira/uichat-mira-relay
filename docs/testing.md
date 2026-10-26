# Tests and module boundaries

Use Node 22 and run `npm install`, then `npm run check` (TypeScript + Vitest
inside the Cloudflare Workers runtime). For watch mode use `npm run test:watch`.

- `src/index.ts`: Worker routing, Durable Object lifecycle and room forwarding.
- `src/protocol.ts`: existing, unchanged V1 path, frame, token and request-id rules.
- `test/protocol.test.ts`: pure protocol contracts and malformed inputs.
- `test/worker.test.ts`: actual workerd Worker entrypoint smoke/rejection checks.

The Verify GitHub Action runs both checks on PRs **before** deploying any
environment. Existing deployment branches and routes are unchanged.

This is the test foundation only. It does **not** add Cloud JWT admission,
WebSocket Host/Client authentication coverage or hosted end-to-end evidence.
REL-001 adds its runtime/negative tests in later scoped PRs, without growing a
single monolithic test file.
