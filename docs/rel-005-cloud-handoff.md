# REL-005 — Cloud Auth ↔ Relay staged transport handoff

Status: **partial live Host-side T3 verified; full Cloud Host+Client / shared-account T3 remains open**.
Owner: [REL-005 #9](https://github.com/uichat-mira/uichat-mira-relay/issues/9).
The protected live probe originated in the research of now-closed, unmerged
Draft PR #16; the supported harness is now on `dev`. This page records the
separate no-secret public JWKS/negative-admission evidence in Draft PR #20
and the shared-Worker two-account probe in Draft PR #22.
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
separate Cloud Grant/Gateway checks remain mandatory. Cloud Client `request`
and `cancel` frames additionally carry the server-authored `relayProvenance`
field documented in [cloud-relay-tickets.md](cloud-relay-tickets.md) for
DSK-007 consumption.

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
| `REL005_FOREIGN_SESSION` | Separate account's eligible Mobile Session; also the second account's Client when the optional two-account gate is enabled |

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

## Shared-service two-account gate (Option A)

**One public Mira Cloud Relay service is shared by different Cloud Accounts.**
Each Account owns its own Desktop Host room and may connect only its own
authorized Mobile device(s). Do not create Worker instances per account, expose
the official Relay URL or room as user settings, or add cross-account delegation.

The Cloud Auth **issuer** enforces account/device/Host/room/role ownership on
ticket issuance (OPS-018/019); the Relay **verifier** enforces signature,
audience, expiry and signed room/role against the socket. A trusted signer
issuing a maliciously misbound ticket is an upstream issuer policy violation,
not a business permission that Relay should try to invent on its own.
Desktop Remote Gateway/Harness separately enforces Host capability scopes.

The `test/cloud-room-socket.test.ts` real-workerd two-account scenario
exercises concurrent independent Host/Client rooms on **one Worker**, same
request IDs without cross-room forwarding, server-authored account provenance
and denial when B attempts to use its valid B-room ticket on A's room URL.
The test uses synthetic signing keys, so it proves Worker/DO transport
isolation rather than real Cloud Auth entitlement or deployed runtime parity.

The optional **live, two-account T3** adds only two extra inputs to the
existing protected `npm run probe:cloud` invocation:

| Variable | Meaning |
| --- | --- |
| `REL005_SECOND_ROOM` | Second Cloud Account's active server-issued Desktop Host room, distinct from `REL005_ROOM` |
| `REL005_SECOND_HOST_SESSION` | Second Account's active device-bound Desktop Host Session, distinct from all other Sessions |

The already-required `REL005_FOREIGN_SESSION` serves as the second
Account's Mobile Client Session. Either both optional inputs are supplied
or neither; partial inputs fail before contacting Cloud Auth. When supplied,
the probe verifies two **valid, account-separated Host+Client ticket pairs**
against the public JWKS, account B's real room/role issuance, denial of A
joining B and B joining A, both pairs' authentic Cloud WebSocket hello/ack,
and same-ID request/complete forwarding with separate server-authored
account/room provenance on the **same** configured `REL005_RELAY_ORIGIN`.
When absent, output explicitly says the B→B positive path was **NOT RUN**.
It does not log real device Sessions, tokens, account IDs or room identifiers.

**Read-only deployment snapshot:** isolated Cloud-only Worker
`uichat-mira-relay-cloud-rel005` has `RELAY_ADMISSION_MODE=cloud`,
`CLOUD_AUTH_JWKS_URL` binding, deployment
`925a02d1-bf73-40e4-ac76-ebf08facf86a` and version
`fd17d8c1-d03e-4fbc-83e5-c219c2e5382f`.
Current production `uichat-mira-relay` has no Cloud admission/JWKS
bindings and remains on Legacy-default deployment
`d281d89b-36ef-4422-846a-bda1e7997897`.
No deployment was changed by this source/test work.
The isolated deployment **predates** the repository's merged
`relayProvenance` identity-forwarding code; do not assume source parity
or treat the older Worker as having passed the latest Desktop Grant ingress.
Version-aligned staging activation needs a separate deployment approval
and real T3 rerun.

**Recorded real evidence:** REL-005 #9 includes a successful, real
device-bound Desktop Host ticket + WebSocket `hello_ack` against the isolated
Cloud-only Worker (`REL005_HOST_T3: PASS`). This proves only the positive
Host-side admission; the Client, A/B isolation, request/cancel, fresh-ticket
reconnect and post-expiry outcomes remain unverified on that deployed version.
The optional two-account live probe also still requires a protected runtime
with actual eligible Sessions and server-owned Host rooms; no secrets are
present in this repository or its GitHub Actions runners.

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
