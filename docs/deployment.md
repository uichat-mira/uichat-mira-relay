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
