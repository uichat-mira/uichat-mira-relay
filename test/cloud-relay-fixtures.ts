// Mirrors uichat-mira/cloud-auth packages/contracts/src/service-credential.ts
// and docs/service-credentials-v0.md; signing keys are generated per test run.
import {
  CompactSign,
  exportJWK,
  generateKeyPair,
  type CompactJWSHeaderParameters,
} from "jose";
import {
  CLOUD_AUTH_SERVICE_CREDENTIAL_ISSUER,
  CLOUD_RELAY_TRANSPORT_AUDIENCE,
  RELAY_TRANSPORT_SCOPE,
  type CloudRelayTicketRole,
} from "../src/cloud-relay-ticket.js";

export const FIXED_NOW = new Date("2026-10-24T10:00:00.000Z");
export const FIXED_NOW_SECONDS = Math.floor(FIXED_NOW.getTime() / 1000);
export const ACCOUNT_ID = "account-0001";
export const DEVICE_ID = "device-0001";
export const KEY_ID = "cloud-auth-2026-10";
export const NEXT_KEY_ID = "cloud-auth-2026-11";
export const ROOM = "room-7f3a";

const encoder = new TextEncoder();

export function relayClaims(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    iss: CLOUD_AUTH_SERVICE_CREDENTIAL_ISSUER,
    sub: ACCOUNT_ID,
    device_id: DEVICE_ID,
    aud: CLOUD_RELAY_TRANSPORT_AUDIENCE,
    scope: [RELAY_TRANSPORT_SCOPE],
    relay: { room: ROOM, role: "client" },
    iat: FIXED_NOW_SECONDS,
    nbf: FIXED_NOW_SECONDS,
    exp: FIXED_NOW_SECONDS + 300,
    ...overrides,
  };
}

export const UPSTREAM_RELAY_CLAIMS_FIXTURE = relayClaims();

export function ticketHeader(
  overrides: Record<string, unknown> = {},
): CompactJWSHeaderParameters {
  return { alg: "EdDSA", typ: "JWT", kid: KEY_ID, ...overrides };
}

export const encodeSegment = (value: string) => {
  let binary = "";
  for (const byte of encoder.encode(value)) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
};

export function manualToken(
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
  signature = "AAAA",
) {
  return `${encodeSegment(JSON.stringify(header))}.${encodeSegment(
    JSON.stringify(claims),
  )}.${signature}`;
}

export async function createSigningFixture(keyId = KEY_ID) {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
  });
  const exported = await exportJWK(publicKey);
  return {
    keyId,
    privateKey,
    publicJwk: { ...exported, use: "sig", alg: "EdDSA", kid: keyId },
  };
}

export async function signTicket(
  privateKey: CryptoKey,
  claims: Record<string, unknown> = relayClaims(),
  protectedHeader: CompactJWSHeaderParameters = ticketHeader(),
) {
  return new CompactSign(encoder.encode(JSON.stringify(claims)))
    .setProtectedHeader(protectedHeader)
    .sign(privateKey);
}

export function jwks(entries: ReadonlyArray<{ kid: string; jwk: Record<string, unknown> }>) {
  return {
    keys: entries.map(({ kid, jwk }) => ({
      ...jwk,
      use: "sig",
      alg: "EdDSA",
      kid,
    })),
  };
}

export function roleContext(role: CloudRelayTicketRole = "client") {
  return { room: ROOM, role };
}
