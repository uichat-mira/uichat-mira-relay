# Mira Relay

Transport-only public relay for Mira Remote Host V1.

Mira Relay is deliberately small: it connects Mira Mobile to a Mira Desktop Host without turning the relay into a Mira cloud backend.

## Boundary

The relay owns only:

- Relay room addressing
- Host / Client WebSocket registration
- Relay connection-token verification
- `request / response / chunk / complete / cancel / error` forwarding

It does **not**:

- run models or Agents
- read Mira Desktop databases
- persist prompts, responses, conversation history, or file bodies
- interpret Remote Host business routes
- authorize `mira_device_*` scopes

Business authorization remains on Mira Desktop.

## Hosted endpoint

The built-in Mira endpoint is intended to run at:

```text
https://relay.tomz.io
```

Health check:

```text
GET https://relay.tomz.io/health
```

WebSocket rooms:

```text
wss://relay.tomz.io/v1/relay/:relayId/socket
```

Users may also deploy this repository to their own Cloudflare Worker / custom domain and configure that HTTPS base URL in Mira Desktop.

## Cloudflare shape

```text
Cloudflare Worker
  -> /health
  -> /v1/relay/:relayId/socket
       -> SQLite-backed Durable Object
       -> Hibernation WebSockets
```

Each `relayId` maps to one Durable Object room. A room accepts one active Desktop Host and multiple Clients.

The room persists only SHA-256 hashes of the Host and Client relay tokens. Request and response bodies are never written to Durable Object storage.

## Development

```bash
npm install
npm run typecheck
npm run dev
```

## Deploy

```bash
npm install
npm run deploy
```

`wrangler.jsonc` binds the Worker to `relay.tomz.io` as a Cloudflare Custom Domain and provisions `RelayRoom` with SQLite-backed Durable Object storage.

After deployment:

```bash
curl https://relay.tomz.io/health
```

Expected response shape:

```json
{
  "ok": true,
  "service": "mira-remote-relay",
  "protocolVersion": 1
}
```

## Frame contract

All frames are JSON and carry `version: 1`.

Client -> Host:

```text
request
cancel
```

Host -> Client:

```text
response
chunk
complete
error
```

The relay rewrites request IDs internally to bind replies to the originating client connection, then restores the client's original request ID on the way back.

## V1 limits

- Max Relay JSON frame: 2 MiB characters
- Max active requests per Client connection: 32
- Desktop-side request body limit: 1 MiB decoded
- Desktop-side cumulative response limit: 16 MiB
- Desktop-side streaming chunk size: 48 KiB before base64 encoding

Large-file transport is intentionally outside Relay V1.

## Security

- Desktop always connects outbound; no public Desktop bind is introduced.
- Relay Host / Client tokens are transport credentials and must never reuse Mira login tokens or `mira_device_*` credentials.
- Business authorization continues to happen on Mira Desktop.
- Relay storage contains only token hashes and minimal room state, never business payloads.
- Shared-service abuse controls / quotas are a separate concern from Remote Host authorization and should stay outside the business protocol.
