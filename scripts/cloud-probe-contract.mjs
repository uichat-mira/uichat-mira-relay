// Pure REL-005 live-probe contract helpers. No credentials are accepted or
// returned here; the caller injects already-authorized Sessions separately.
export const RELAY_AUDIENCE = "mira:cloud-relay-transport";
export const RELAY_ISSUER = "mira:cloud-auth";
export const SHIYAN_AUDIENCE = "mira:cloud-shiyan";
export const RELAY_TRANSPORT_SCOPE = "relay:transport";
export const MAX_TICKET_LENGTH = 8 * 1024;
export const MAX_TICKET_TTL_SECONDS = 600;
export const ROOM_PATTERN = /^[A-Za-z0-9_-]{16,128}$/u;
export const KID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/u;
export const ERROR_CODE_PATTERN = /^[A-Z0-9_]{3,80}$/u;
const BASE64URL_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/u;
const ED25519_JWK_X_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const HEADER_FIELDS = ["alg", "kid", "typ"];
const CLAIM_FIELDS = [
  "aud", "device_id", "exp", "iat", "iss", "nbf", "relay", "scope", "sub",
];
const JWK_FIELDS = ["alg", "crv", "kid", "kty", "use", "x"];
const STAGES = new Set([
  "CONFIG", "JWKS", "ISSUANCE", "TICKET", "ADMISSION", "TRANSPORT",
]);

const isRecord = (value) =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const sortedKeys = (value) => Object.keys(value).sort((a, b) => a.localeCompare(b));

const exactFields = (value, fields) => {
  const keys = sortedKeys(value);
  const expected = [...fields].sort((a, b) => a.localeCompare(b));
  return keys.length === expected.length &&
    keys.every((key, index) => key === expected[index]);
};

export class ProbeError extends Error {
  constructor(stage, message) {
    super(message);
    this.name = "ProbeError";
    this.stage = STAGES.has(stage) ? stage : "UNKNOWN";
  }
}

export const fail = (stage, message) => {
  throw new ProbeError(stage, message);
};

export function failureCategory(error) {
  return error instanceof ProbeError ? error.stage : "UNKNOWN";
}

export function redactDiagnostic(error) {
  const message = error instanceof Error ?
    error.message : (typeof error === "string" ? error : "unknown failure");
  return message
    .replace(/Bearer\s+\S+/giu, "Bearer [REDACTED]")
    .replace(/\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu,
      "[REDACTED_JWT]")
    .replace(/(\/v1\/relay\/)[^/\s?]+(\/socket)/gu, "$1[REDACTED_ROOM]$2")
    .replace(/\b[A-Za-z0-9_-]{32,}\b/gu, "[REDACTED]")
    .replace(/\s+/gu, " ")
    .slice(0, 300);
}

function bareOrigin(env, name, scheme) {
  const input = env[name];
  if (typeof input !== "string" || input.length === 0) {
    fail("CONFIG", `${name} is required`);
  }
  let url;
  try {
    url = new URL(input);
  } catch {
    fail("CONFIG", `${name} must be an absolute URL`);
  }
  if (
    url.protocol !== scheme ||
    url.username !== "" ||
    url.password !== "" ||
    (url.pathname !== "/" && url.pathname !== "") ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    fail("CONFIG", `${name} must be a bare ${scheme}// origin`);
  }
  return url.origin;
}

export function parseProbeConfig(env) {
  if (!isRecord(env)) fail("CONFIG", "probe environment is required");
  const auth = bareOrigin(env, "REL005_AUTH_ORIGIN", "https:");
  const relay = bareOrigin(env, "REL005_RELAY_ORIGIN", "wss:");
  if (new URL(relay).hostname === "relay.tomz.io") {
    fail("CONFIG", "live probe must not target the Legacy production Relay");
  }
  const room = env.REL005_ROOM;
  if (typeof room !== "string" || !ROOM_PATTERN.test(room)) {
    fail("CONFIG", "REL005_ROOM is invalid");
  }
  const sessions = {
    host: env.REL005_HOST_SESSION,
    client: env.REL005_CLIENT_SESSION,
    foreign: env.REL005_FOREIGN_SESSION,
  };
  for (const [name, value] of Object.entries(sessions)) {
    if (typeof value !== "string" || value.length === 0) {
      fail("CONFIG", `REL005_${name.toUpperCase()}_SESSION is required`);
    }
  }
  if (new Set(Object.values(sessions)).size !== 3) {
    fail("CONFIG", "Host, Client and foreign Sessions must be distinct");
  }
  return { auth, relay, room, sessions };
}

export function errorCode(payload) {
  if (!isRecord(payload) || !isRecord(payload.error)) return "INVALID_ERROR";
  const code = payload.error.code;
  return typeof code === "string" && ERROR_CODE_PATTERN.test(code) ?
    code : "INVALID_ERROR";
}

function decodeSegment(segment) {
  if (!BASE64URL_SEGMENT_PATTERN.test(segment)) {
    fail("TICKET", "credential is not canonical base64url");
  }
  let binary;
  try {
    const base64 = segment.replace(/-/gu, "+").replace(/_/gu, "/");
    binary = atob(`${base64}${"=".repeat((4 - (base64.length % 4)) % 4)}`);
  } catch {
    fail("TICKET", "credential is not canonical base64url");
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  const canonical = btoa(binary)
    .replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
  if (canonical !== segment) fail("TICKET", "credential is not canonical base64url");
  return bytes;
}

function decodeJson(segment, label) {
  const bytes = decodeSegment(segment);
  let value;
  try {
    value = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    fail("TICKET", `${label} is not valid JSON`);
  }
  if (!isRecord(value)) fail("TICKET", `${label} must be a JSON object`);
  return value;
}

export async function importJwks(payload) {
  if (!isRecord(payload) || !exactFields(payload, ["keys"]) ||
    !Array.isArray(payload.keys) || payload.keys.length < 1 || payload.keys.length > 8) {
    fail("JWKS", "JWKS must expose a bounded keys array");
  }
  const keys = new Map();
  for (const entry of payload.keys) {
    if (!isRecord(entry) || !exactFields(entry, JWK_FIELDS)) {
      fail("JWKS", "unexpected JWKS key shape");
    }
    if (
      entry.kty !== "OKP" ||
      entry.crv !== "Ed25519" ||
      entry.alg !== "EdDSA" ||
      entry.use !== "sig" ||
      typeof entry.kid !== "string" ||
      !KID_PATTERN.test(entry.kid) ||
      typeof entry.x !== "string" ||
      !ED25519_JWK_X_PATTERN.test(entry.x)
    ) {
      fail("JWKS", "invalid public JWKS key");
    }
    if (keys.has(entry.kid)) fail("JWKS", "duplicate JWKS kid");
    let key;
    try {
      key = await crypto.subtle.importKey(
        "jwk",
        { kty: entry.kty, crv: entry.crv, x: entry.x },
        { name: "Ed25519" },
        false,
        ["verify"],
      );
    } catch {
      fail("JWKS", "JWKS public key could not be imported");
    }
    keys.set(entry.kid, key);
  }
  return keys;
}

async function verifyJwt(token, keys, expected) {
  if (typeof token !== "string" || token.length > MAX_TICKET_LENGTH) {
    fail("TICKET", "credential is not a bounded compact JWT");
  }
  const parts = token.split(".");
  if (parts.length !== 3) fail("TICKET", "credential is not compact JWS");
  const header = decodeJson(parts[0], "JWT header");
  const claims = decodeJson(parts[1], "JWT payload");
  if (
    !exactFields(header, HEADER_FIELDS) ||
    header.alg !== "EdDSA" ||
    header.typ !== "JWT" ||
    typeof header.kid !== "string" ||
    !KID_PATTERN.test(header.kid)
  ) {
    fail("TICKET", "JWT header is not EdDSA/JWT with a bounded kid");
  }
  const key = keys.get(header.kid);
  if (key === undefined) fail("TICKET", "ticket kid is absent from trusted JWKS");
  const signature = decodeSegment(parts[2]);
  let valid = false;
  try {
    valid = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      signature,
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    );
  } catch {
    fail("TICKET", "ticket signature could not be verified");
  }
  if (!valid) fail("TICKET", "ticket signature is invalid");
  if (claims.iss !== expected.issuer) fail("TICKET", "ticket issuer mismatch");
  if (claims.aud !== expected.audience) fail("TICKET", "ticket audience mismatch");
  return claims;
}

export async function verifyTicket(token, keys, expected) {
  const claims = await verifyJwt(token, keys, {
    issuer: RELAY_ISSUER,
    audience: RELAY_AUDIENCE,
  });
  if (!exactFields(claims, CLAIM_FIELDS) ||
    !Array.isArray(claims.scope) ||
    claims.scope.length !== 1 ||
    claims.scope[0] !== RELAY_TRANSPORT_SCOPE ||
    !isRecord(claims.relay) ||
    !exactFields(claims.relay, ["room", "role"]) ||
    typeof claims.sub !== "string" || claims.sub.length === 0 ||
    typeof claims.device_id !== "string" || claims.device_id.length === 0 ||
    !Number.isInteger(claims.iat) ||
    !Number.isInteger(claims.nbf) ||
    !Number.isInteger(claims.exp) ||
    claims.nbf < claims.iat ||
    claims.exp <= claims.nbf) {
    fail("TICKET", "ticket claims do not satisfy the Relay transport contract");
  }
  if (claims.relay.room !== expected.room) fail("TICKET", "ticket room mismatch");
  if (claims.relay.role !== expected.role) fail("TICKET", "ticket role mismatch");
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (claims.exp <= nowSeconds) fail("TICKET", "ticket has expired");
  if (claims.exp - claims.iat > MAX_TICKET_TTL_SECONDS) {
    fail("TICKET", "ticket lifetime exceeds the Relay transport limit");
  }
  return claims;
}

export async function verifyShiyanClaims(token, keys) {
  const claims = await verifyJwt(token, keys, {
    issuer: RELAY_ISSUER,
    audience: SHIYAN_AUDIENCE,
  });
  if (typeof claims.sub !== "string" || claims.sub.length === 0) {
    fail("TICKET", "Shiyan ticket does not identify an account");
  }
  return claims;
}
