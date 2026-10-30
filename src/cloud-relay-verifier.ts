import { compactVerify, decodeProtectedHeader } from "jose";
import { createCloudRelayJwksCache } from "./cloud-relay-jwks.js";
import {
  CLOUD_AUTH_SERVICE_CREDENTIAL_ISSUER,
  CLOUD_RELAY_MAX_CLOCK_SKEW_SECONDS,
  CLOUD_RELAY_TICKET_MAX_LENGTH,
  CLOUD_RELAY_TICKET_MAX_TTL_SECONDS,
  CLOUD_RELAY_TRANSPORT_AUDIENCE,
  RELAY_TRANSPORT_SCOPE,
  cloudRelayTicketError,
  isCloudAuthKeyId,
  isCloudRelayRoom,
  isCloudRelayTicketRole,
  isRecord,
  type CloudRelayTicketContext,
  type CloudRelayTicketIdentity,
  type CloudRelayTicketRole,
} from "./cloud-relay-ticket.js";

const BASE64URL_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/u;
const HEADER_FIELDS = ["alg", "kid", "typ"] as const;
const CLAIM_FIELDS = [
  "aud",
  "device_id",
  "exp",
  "iat",
  "iss",
  "nbf",
  "relay",
  "scope",
  "sub",
] as const;
const RELAY_FIELDS = ["role", "room"] as const;

type RelayClaims = Readonly<{
  iss: string;
  sub: string;
  device_id: string;
  aud: string;
  scope: readonly string[];
  relay: CloudRelayTicketContext;
  iat: number;
  nbf: number;
  exp: number;
}>;

export type CloudRelayTicketVerifierConfig = {
  jwksUrl: string;
  fetchImpl?: typeof fetch;
  now?: () => Date;
  clockSkewSeconds?: number;
  jwksCacheSeconds?: number;
};

export type CloudRelayTicketVerifier = Readonly<{
  verify(
    token: string,
    expected: CloudRelayTicketContext,
  ): Promise<CloudRelayTicketIdentity>;
}>;

const isCanonicalBase64Url = (value: string) => {
  if (!BASE64URL_SEGMENT_PATTERN.test(value)) return false;
  try {
    const base64 = value.replace(/-/gu, "+").replace(/_/gu, "/");
    const padded = `${base64}${"=".repeat((4 - (base64.length % 4)) % 4)}`;
    const binary = atob(padded);
    return btoa(binary)
      .replace(/\+/gu, "-")
      .replace(/\//gu, "_")
      .replace(/=+$/u, "") === value;
  } catch {
    return false;
  }
};

const hasExactFields = (value: Record<string, unknown>, fields: readonly string[]) => {
  const keys = Object.keys(value);
  return keys.length === fields.length && keys.every((key) => fields.includes(key));
};

const parseHeader = (token: string) => {
  let raw: unknown;
  try {
    raw = decodeProtectedHeader(token);
  } catch {
    cloudRelayTicketError("INVALID_HEADER", "JWT header is not valid JSON");
  }

  if (
    !isRecord(raw) ||
    !hasExactFields(raw, HEADER_FIELDS) ||
    raw.alg !== "EdDSA" ||
    raw.typ !== "JWT" ||
    !isCloudAuthKeyId(raw.kid)
  ) {
    cloudRelayTicketError(
      "INVALID_HEADER",
      "JWT header must be EdDSA/JWT with a bounded kid",
    );
  }

  return raw.kid;
};

const parseClaims = (payload: Uint8Array): RelayClaims => {
  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder().decode(payload)) as unknown;
  } catch {
    cloudRelayTicketError("INVALID_CLAIMS", "JWT payload is not valid JSON");
  }

  if (
    !isRecord(raw) ||
    !hasExactFields(raw, CLAIM_FIELDS) ||
    typeof raw.iss !== "string" ||
    raw.iss.length === 0 ||
    raw.iss.length > 256 ||
    typeof raw.sub !== "string" ||
    raw.sub.length === 0 ||
    raw.sub.length > 128 ||
    typeof raw.device_id !== "string" ||
    raw.device_id.length === 0 ||
    raw.device_id.length > 128 ||
    typeof raw.aud !== "string" ||
    raw.aud.length === 0 ||
    raw.aud.length > 256 ||
    !Array.isArray(raw.scope) ||
    raw.scope.length !== 1 ||
    raw.scope[0] !== RELAY_TRANSPORT_SCOPE ||
    !isRecord(raw.relay) ||
    !hasExactFields(raw.relay, RELAY_FIELDS) ||
    !isCloudRelayRoom(raw.relay.room) ||
    !isCloudRelayTicketRole(raw.relay.role) ||
    !Number.isInteger(raw.iat) ||
    !Number.isInteger(raw.nbf) ||
    !Number.isInteger(raw.exp) ||
    (raw.iat as number) < 0 ||
    (raw.nbf as number) < 0 ||
    (raw.exp as number) < 0
  ) {
    cloudRelayTicketError(
      "INVALID_CLAIMS",
      "JWT payload does not satisfy the canonical Relay ticket contract",
    );
  }

  const claims = raw as unknown as RelayClaims;
  if (claims.nbf < claims.iat) {
    cloudRelayTicketError("INVALID_CLAIMS", "JWT nbf must not precede iat");
  }
  if (claims.exp <= claims.nbf) {
    cloudRelayTicketError("INVALID_CLAIMS", "JWT exp must be after nbf");
  }

  return claims;
};

const validateExpectedContext = (value: unknown): CloudRelayTicketContext => {
  if (
    !isRecord(value) ||
    !hasExactFields(value, RELAY_FIELDS) ||
    !isCloudRelayRoom(value.room) ||
    !isCloudRelayTicketRole(value.role)
  ) {
    cloudRelayTicketError(
      "INVALID_VERIFIER_CONFIG",
      "Expected Relay room and role must be configured explicitly",
    );
  }
  return { room: value.room, role: value.role };
};

const validateClockSkew = (value: number) => {
  if (
    !Number.isInteger(value) ||
    value < 0 ||
    value > CLOUD_RELAY_MAX_CLOCK_SKEW_SECONDS
  ) {
    cloudRelayTicketError(
      "INVALID_VERIFIER_CONFIG",
      `Clock skew must be an integer between 0 and ${CLOUD_RELAY_MAX_CLOCK_SKEW_SECONDS} seconds`,
    );
  }
  return value;
};

const parseCompactToken = (token: string) => {
  if (
    typeof token !== "string" ||
    token.length === 0 ||
    token.length > CLOUD_RELAY_TICKET_MAX_LENGTH
  ) {
    cloudRelayTicketError("MALFORMED_TOKEN", "Relay ticket must be a compact JWS");
  }
  const segments = token.split(".");
  if (segments.length !== 3 || !segments.every(isCanonicalBase64Url)) {
    cloudRelayTicketError("MALFORMED_TOKEN", "Relay ticket must be a compact JWS");
  }
  return token;
};

export function createCloudRelayTicketVerifier(
  config: CloudRelayTicketVerifierConfig,
): CloudRelayTicketVerifier {
  if (!isRecord(config)) {
    cloudRelayTicketError("INVALID_VERIFIER_CONFIG", "Verifier configuration is required");
  }

  const clockSkewSeconds = validateClockSkew(config.clockSkewSeconds ?? 0);
  const now = config.now ?? (() => new Date());
  const cache = createCloudRelayJwksCache({
    jwksUrl: config.jwksUrl,
    now: () => now().getTime(),
    ...(config.fetchImpl === undefined ? {} : { fetchImpl: config.fetchImpl }),
    ...(config.jwksCacheSeconds === undefined
      ? {}
      : { maxAgeSeconds: config.jwksCacheSeconds }),
  });

  return {
    async verify(token, expected) {
      const expectedContext = validateExpectedContext(expected);
      const ticket = parseCompactToken(token);

      const kid = parseHeader(ticket);
      const publicKey = await cache.getKey(kid);

      let payload: Uint8Array;
      try {
        const verified = await compactVerify(ticket, publicKey, {
          algorithms: ["EdDSA"],
        });
        payload = verified.payload;
      } catch {
        cloudRelayTicketError("INVALID_SIGNATURE", "Relay ticket signature is invalid");
      }

      const claims = parseClaims(payload);

      if (claims.iss !== CLOUD_AUTH_SERVICE_CREDENTIAL_ISSUER) {
        cloudRelayTicketError("ISSUER_MISMATCH", "Relay ticket issuer is not trusted");
      }
      if (claims.aud !== CLOUD_RELAY_TRANSPORT_AUDIENCE) {
        cloudRelayTicketError(
          "AUDIENCE_MISMATCH",
          "Relay ticket audience is not accepted by this verifier",
        );
      }

      const currentTime = now().getTime();
      if (!Number.isFinite(currentTime)) {
        cloudRelayTicketError(
          "INVALID_VERIFIER_CONFIG",
          "Verifier clock must provide a valid time",
        );
      }
      const nowSeconds = Math.floor(currentTime / 1000);

      if (claims.iat > nowSeconds + clockSkewSeconds) {
        cloudRelayTicketError("IAT_IN_FUTURE", "Relay ticket was issued in the future");
      }
      if (claims.nbf > nowSeconds + clockSkewSeconds) {
        cloudRelayTicketError("NOT_YET_VALID", "Relay ticket is not valid yet");
      }
      if (claims.exp <= nowSeconds - clockSkewSeconds) {
        cloudRelayTicketError("EXPIRED", "Relay ticket has expired");
      }
      if (claims.exp - claims.iat > CLOUD_RELAY_TICKET_MAX_TTL_SECONDS) {
        cloudRelayTicketError(
          "TTL_EXCEEDED",
          "Relay ticket lifetime exceeds the verifier limit",
        );
      }

      if (
        claims.relay.room !== expectedContext.room ||
        claims.relay.role !== expectedContext.role
      ) {
        cloudRelayTicketError(
          "RELAY_CONTEXT_MISMATCH",
          "Relay ticket does not match the requested connection",
        );
      }

      const identity: CloudRelayTicketIdentity = {
        accountId: claims.sub,
        deviceId: claims.device_id,
        room: claims.relay.room,
        role: claims.relay.role as CloudRelayTicketRole,
        expiresAt: new Date(claims.exp * 1000),
      };
      return Object.freeze(identity);
    },
  };
}
