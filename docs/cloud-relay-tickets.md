# Cloud Relay ticket verification

This repository contains an isolated verifier for Cloud Auth Relay transport
tickets. It is not yet wired into Durable Object `hello`, Worker routing or the
Legacy Relay V1 token path.

## Canonical trust

Relay tickets are Cloud Auth service credentials with these fixed values:

| Field | Value |
| --- | --- |
| Issuer | `mira:cloud-auth` |
| Audience | `mira:cloud-relay-transport` |
| Scope | `relay:transport` |
| Algorithm | `EdDSA` (Ed25519) |
| Header type | `JWT` |

The verifier trusts only the configured HTTPS JWKS URL. It never reads a JWKS
URL, `jku`, `jwk`, key material or signing algorithm from the ticket. The `kid`
header only selects a key from the fetched trusted key set.

A successful verification returns only:

```text
accountId, deviceId, room, role, expiresAt
```

The raw ticket, Cloud Session and JWKS response body are not persisted or
logged.

## Ticket validation

The verifier rejects malformed compact JWS values, tickets longer than 8 KiB,
unsafe or extra header fields, an untrusted `kid`, invalid signatures,
non-canonical claims, an untrusted issuer or audience, an unexpected scope,
missing or mismatched `relay.room` / `relay.role`, invalid temporal claims and
an invalid verifier clock.

The ticket must match the actual connection context. A Relay ticket is
transport-only and cannot grant Host Tool, Browser, Terminal, Agent or other
business permissions.

Cloud Auth's V0 ticket defaults to a 300 second lifetime and must never exceed
600 seconds. The verifier accepts the default and rejects a longer lifetime.
Clock skew defaults to zero and is limited to 60 seconds.

## JWKS cache and rotation

The trusted JWKS cache is bounded:

- public HTTPS URL only, with no URL credentials, query or fragment;
- fetch uses Workers-supported `redirect: "manual"` and rejects all non-2xx
  responses, including redirects, without following their `Location`;
- fetch uses `GET`, bypasses the platform cache and reads at most 64 KiB;
- a single 5-second default deadline (bounded to 1–10,000 ms in cache configuration)
  covers both the response headers and streaming response body; timeout aborts
  the request and fails closed with `JWKS_UNAVAILABLE`;
- at most 8 public Ed25519 signing keys;
- each JWK must be `OKP` / `Ed25519` / `sig` / `EdDSA` with a bounded `kid`;
- a fresh key set is reused for at most 300 seconds;
- concurrent cache misses share one in-flight fetch.

The published V0 JWKS lifetime is 300 seconds. Refresh happens when the cache
reaches that age. An unknown `kid` on a fresh cache fails closed without
fetching again, so a ticket cannot force arbitrary key lookups.

Key rotation uses Cloud Auth's pre-publication strategy:

1. publish the next public key while the old key still signs;
2. wait at least the 300 second JWKS cache lifetime plus deployment
   propagation;
3. switch signing to the new key while both public keys remain published;
4. after the last old-key ticket can expire, wait the 600 second maximum ticket
   lifetime plus the 300 second JWKS cache lifetime, then retire the old public
   key.

A missing, malformed, non-2xx or unreachable JWKS fails closed. An expired
cache is never used as a stale fallback, and there is no unsigned, token-selected
key or Legacy Relay token fallback.

## Verification

```bash
npm install --legacy-peer-deps --no-audit --no-fund
npm run check
```

The verifier tests run in the Cloudflare Workers Vitest runtime so Ed25519
verification exercises Workerd WebCrypto through `jose`. Tests generate
ephemeral key pairs and **locally mirror** the upstream Cloud Auth claim schema.
The locally signed fixture is **not** proof of interoperability with a token
issued by the real Cloud Auth Node signer. That evidence belongs to REL-005
cross-repository acceptance. No real ticket, private key or deployment secret
is committed.

Wiring the verified identity into Cloud room admission and any production
Cloud activation remain separate work items.
