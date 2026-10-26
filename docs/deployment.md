# Cloudflare deployment

The hosted Mira Relay is configured for:

```text
https://relay.tomz.io
```

`wrangler.jsonc` declares `relay.tomz.io` as a Cloudflare Worker Custom Domain and provisions `RelayRoom` with SQLite-backed Durable Object storage.

## GitHub Actions credentials

Add these repository Actions secrets:

```text
CLOUDFLARE_ACCOUNT_ID
CLOUDFLARE_API_TOKEN
```

Cloudflare recommends using an API token scoped to the target account / zone and the Workers edit permissions required by Wrangler deployment. Do not commit the token to the repository.

The repository workflow always installs dependencies and runs TypeScript checking. On `main` / manual dispatch, deployment only runs when both Cloudflare secrets are present.

## Deploy manually

```bash
npm install
npm run typecheck
npm run deploy
```

For local interactive authentication, Wrangler can use `wrangler login`. CI should use the two environment variables above instead.

## Verify

```bash
curl https://relay.tomz.io/health
```

Expected shape:

```json
{
  "ok": true,
  "service": "mira-remote-relay",
  "protocolVersion": 1
}
```

Then verify a Host WebSocket can connect to:

```text
wss://relay.tomz.io/v1/relay/<relayId>/socket
```

No Mira business payload should be persisted by the Relay Durable Object.


## Admission modes (REL-004, implementation only)

Relay selects its WebSocket admission mode **only from trusted Worker environment
configuration**, never from JWT headers or client requests.

- **Legacy/self-hosted**: `RELAY_ADMISSION_MODE=legacy` and no
  `CLOUD_AUTH_JWKS_URL`. Existing deployments that set neither variable stay
  Legacy V1 for compatibility. Legacy `hostToken`/`clientToken` provisioning,
  hash storage and self-hosted clients behave as before.
- **Official Cloud-only**: set `RELAY_ADMISSION_MODE=cloud` and a fixed
  `CLOUD_AUTH_JWKS_URL=https://<trusted-cloud-auth-host>/.well-known/jwks.json`
  on that *deployment*. No token-provided key URL, no Legacy token fallback.
  A partially configured or unknown mode refuses socket upgrades (503).
  Cloud Host and Client both send V1
  `hello {version:1,type:"hello",role,relayId,token:"<Cloud Relay JWT>"}`;
  **do not** include legacy `clientToken`. V1 `hello_ack` stays unchanged
  after verifying EdDSA, audience, scope, room and role.
- Internal DO naming in Cloud mode is `cloud:<relayId>`, while Legacy stays
  `<relayId>`. This physically separates connected sockets and stored token
  hashes even when both modes have the same visible room ID.
- Cloud admission failures return bounded `CLOUD_TICKET_REQUIRED`,
  `CLOUD_INVALID_HELLO`, `CLOUD_TICKET_REJECTED` or
  `CLOUD_AUTH_UNAVAILABLE` errors and close with policy code 1008. Expiration
  gates **new/reconnected** WebSockets; an already accepted connection is
  not closed solely on ticket expiry.
- REL-003's JWKS verifier has a bounded GET/response deadline. Optional
  `RELAY_JWKS_SERVICE` is an operator-owned internal service binding to fetch
  that **same fixed URL**, used only by the isolated workerd integration
  tests here; ordinary Cloud mode uses external `fetch`.

**Deployment safety:** Do not switch `relay.tomz.io` to Cloud mode while
Legacy consumers still require it. This card adds capability and regression
tests only. Test and production environment selection, Cloud Auth ticket
issuance, Desktop/Mobile connectivity and key rotation require separate
approval/REL-005 integration evidence. Legacy clients do not automatically
connect to Cloud mode; Cloud mode does not fall back to Legacy or Tailscale.
Transport tickets never grant Host tools/Browser/Terminal/Agent permissions.

Verification uses `npm run check`, which exercises the original Legacy
workerd suite and a separate Cloud-mode DO/WebSocket suite with ephemeral
test signing keys. This verifies Relay admission/forwarding, **not** an actual
Cloud Auth Node-issued production ticket or Mobile network session.
