# REL-005 — Cloud Auth ↔ Relay staged transport handoff

Status: **implementation/contract preparation**, not a live Cloud admission acceptance.
Owner: [REL-005 #9](https://github.com/uichat-mira/uichat-mira-relay/issues/9).
This is the proposed successor to Draft PR #16 (reusing its probe/document
direction at head `09fdd48`); #16 remains open until the maintainer decides.
Do not use this page to enable Cloud mode in production.

## What was inspected (2026-10-26)

- Cloud Auth: `packages/contracts/src/service-credential.ts`,
  `apps/api/src/service-credentials/{service,relay-admission,signer,routes}.ts`,
  and `apps/api/src/hosts/{host-repository,host-presence}.ts`.
- Relay: `src/{worker,room,cloud-room-admission,cloud-relay-verifier}.ts`
  and real-workerd admission tests from REL-004.
- Desktop: `server/src/services/remote-relay-connector.service.ts`,
  `cloud-relay-ticket-ipc.service.ts`, and the DSK-010 IPC contract.
- Mobile: `src/api/remoteRelay.ts` and MOB-080 #274; Mobile Cloud Client
  connection has **not** been completed by this Relay work.

### Protocol identity

Cloud Auth `POST /v1/service-credentials` accepts a device-bound Session and:

```json
{"audience":"mira:cloud-relay-transport","relay":{"room":"<server-owned-room>","role":"host"}}
```

A separate same-account Mobile Session requests the identical room with
`role:"client"`. The issuer signs a compact EdDSA JWT with
`iss=mira:cloud-auth`, `aud=mira:cloud-relay-transport`,
`scope=["relay:transport"]`, `sub`, `device_id`,
`relay:{room,role}`, and `iat/nbf/exp`. The Relay `hello` is:

```json
{"version":1,"type":"hello","role":"host","relayId":"<server-owned-room>","token":"<JWT>"}
```

For Client, only `role` and the JWT change. Cloud `hello` must not send
`clientToken`. The path is `wss://<isolated-relay>/v1/relay/<room>/socket`;
`hello_ack` remains the V1 frame with `role`, `relayId` and
`protocolVersion:1`. Denial is a bounded error and close code 1008.
A transport ticket **never** grants Desktop business capabilities. Desktop's
separate Cloud Grant/Gateway checks remain mandatory.

Cloud Auth's server-owned Host room is `room_` plus random base64url bytes:
it satisfies Relay's stricter URL room regex `[A-Za-z0-9_-]{16,128}`, even
though Cloud Auth's general schema permits some other room characters.
The real Host registration/lease must be available while obtaining tickets.

### Confirmed deployment prerequisites

At inspection, the Cloudflare `uichat-mira-relay-dev`,
`uichat-mira-relay-test` and `uichat-mira-relay` Workers had
only the `RELAY_ROOMS` Durable Object binding, **no**
`RELAY_ADMISSION_MODE` or `CLOUD_AUTH_JWKS_URL`.
Therefore they default to Legacy mode, including the newly deployed REL-004
`dev` code. CI alone does not show Cloud-mode live admission.

Cloud Auth's Caddy prod/test templates had an `@api` matcher for only
`/health /ready /v1/*`, but Fastify registers public
`/.well-known/jwks.json` outside `/v1`. Thus the source templates route
JWKS to the Portal static fallback, not to Fastify. The minimal fix lives in
Cloud Auth's REL-005 prerequisite Draft PR and must be promoted/verified
through the owning Cloud Auth release process **before** a live Relay trial.
The runtime Caddy snippet may differ; inspect it rather than assuming.

Cloud Auth's **test and production deployments share their host and loopback
port 8788**. Do not run the Cloud Auth test deploy over the production instance.
Use an approved maintenance window or a genuinely independent Auth endpoint.

### Staging gates — no implicit deployment authorization

1. Verify actual HTTPS Cloud Auth JWKS ingress serves status 200 and a JSON
   `keys` array with public OKP/Ed25519 JWK entries, not React HTML or
   `SERVICE_CREDENTIAL_UNAVAILABLE`. Confirm TLS and trusted hostname.
2. Choose a dedicated Cloud-only Relay staging Worker/hostname without
   displacing known Legacy dev/test consumers. Record a **deployment version**,
   existing bindings and rollback anchor first.
3. Configure `RELAY_ADMISSION_MODE=cloud` plus
   `CLOUD_AUTH_JWKS_URL=https://<approved-auth-host>/.well-known/jwks.json`.
   Use the actual trusted Auth origin. Never let the JWT or client request
   supply this URL. This is a deployment-level mode switch, not a per-socket
   fallback. Do not change prod `relay.tomz.io`.
4. Verify TLS/WSS reachability, actual account/host association and signed
   ticket issuance before starting the probe. Avoid recording bearer tokens,
   room identifiers or private keys in logs, Issues or shell command history.
5. Use only a **separate verified staging Worker**, not the production
   Legacy service. On failure restore prior version/bindings with an approved
   rollback procedure and re-check Legacy clients. Retaining a stale JWKS
   cache across key rotation requires pre-publication, >=300 seconds overlap
   and expiry of old tickets (maximum 600 seconds); do not rotate keys as an
   incidental test.

## Explicit live probe (opt-in; credentials never logged)

The repository offers `npm run probe:cloud`, implemented in
`scripts/verify-live-cloud-admission.mjs` with contract helpers in
`scripts/cloud-probe-contract.mjs`, for Node 22 or newer. It is **not**
executed by CI, because it requires real authorized device Sessions and
creates transient tickets and WebSockets.

The probe and helpers are the proposed successor to Draft PR #16. They keep
the same live contract but fail closed with one bounded stage category:
`CONFIG`, `JWKS`, `ISSUANCE`, `TICKET`, `ADMISSION`, `TRANSPORT` or
`UNKNOWN`. Diagnostics redact `Bearer` values, compact JWT material and Relay
room paths, never print server bodies or stack traces, and truncate the
message. There is no fallback from HTTPS JWKS to a local key, from Cloud to
Legacy admission, or from a missing/denied ticket to an unauthenticated
socket.

Deterministic `test/cloud-probe-contract.test.ts` workerd tests cover bare
origin/room/session configuration, production-host refusal, bounded error
codes, diagnostic redaction, real EdDSA ticket verification, wrong
room/role/audience/expiry/signature/key cases, Shiyan audience separation and
Portal-HTML/duplicate/non-Ed25519 JWKS rejection. These test the **probe
harness contract only**; REL-004's real workerd admission tests remain the
runtime admission evidence and are not duplicated here. `npm run check` also
syntax-checks both probe modules. The three PR #16
`javascript:S2871` reliability findings (`Object.keys(...).sort()` without a
comparator) are removed; every lexical sort now uses `localeCompare`.

Supply these variables through a trusted local secret-injection mechanism,
**not committed .env files or CI logs**:

| Variable | Meaning |
| --- | --- |
| `REL005_AUTH_ORIGIN` | Bare trusted HTTPS Cloud Auth ingress, no path |
| `REL005_RELAY_ORIGIN` | Bare WSS staging Worker origin (production host blocked) |
| `REL005_ROOM` | Currently available authoritative Desktop Host room |
| `REL005_HOST_SESSION` | Active same-room owner Desktop device-bound Session |
| `REL005_CLIENT_SESSION` | Same-account eligible Mobile device-bound Session |
| `REL005_FOREIGN_SESSION` | Separate account's eligible Mobile Session |

The script fetches real HTTPS JWKS, uses the public Ed25519 key to verify
Cloud Auth's **actual issued** Host/Client JWT signatures and context,
checks upstream foreign-account/role/room ticket denials, and runs the
Cloud-only Worker/DO Host/Client handshake. Its network session uses a
**synthetic Host WebSocket fixture** to check request/complete/cancel;
this does not claim the packaged Desktop process connected.

Additional negatives: use a Client ticket as Host, use its correct JWT on
a different URL room, supply a Shiyan-audience signed token, and try an old
Legacy token. All must deny before usable admission. Use optional
`npm run probe:cloud -- --expiry` only in an approved longer test window:
the probe waits past actual ticket expiry, ensures the established socket
still forwards, and verifies that reopening with that expired ticket fails.
Normal invocation explicitly marks expiry **NOT RUN**.

Do **not** interpret a failed public JWKS request, 503 keyring, absent
Host lease, missing credentials, or Legacy-mode 101 response as success.
Record only bounded case outcomes, target Worker version, date and testing
network, **not** identities/credential values.

## Evidence still required for REL-005 acceptance

- [ ] Live Caddy HTTPS JWKS route and real keyring reachable; template PR is
  **not** itself deployment evidence.
- [ ] Actual isolated Cloud-mode Worker version, bindings, TLS and rollback
  verified; existing Legacy prod untouched.
- [ ] Real issued Host and Client credentials accepted at Worker/DO; signed
  wrong-role/room/audience/expired and foreign-account *issuance* denials.
- [ ] Forward/complete/cancel/Host replacement/reconnect checked on live
  runtime; verified long-lived socket expiry behavior and JWKS rotation plan.
- [ ] Consumer handoff to DSK-006 and MOB-080 with exact endpoint/error
  contract and unproven Mobile business T4 called out separately.

Existing REL-003/004 workerd unit/integration fixtures are useful regression
checks, **not** evidence that any of the boxes above already passed.
