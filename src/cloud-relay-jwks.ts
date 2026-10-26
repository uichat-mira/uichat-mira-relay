import { importJWK } from "jose";
import {
  CLOUD_AUTH_JWKS_CACHE_SECONDS,
  CLOUD_AUTH_JWKS_MAX_BYTES,
  CLOUD_AUTH_JWKS_MAX_KEYS,
  CloudRelayTicketVerificationError,
  cloudRelayTicketError,
  isCloudAuthKeyId,
  isRecord,
} from "./cloud-relay-ticket.js";

const ED25519_JWK_X_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const JWK_FIELDS = ["alg", "crv", "kid", "kty", "use", "x"] as const;

type TrustedKey = Readonly<{
  publicKey: CryptoKey;
}>;

type JwksSnapshot = Readonly<{
  keys: ReadonlyMap<string, TrustedKey>;
  fetchedAtMs: number;
}>;

export type CloudRelayJwksCacheOptions = {
  jwksUrl: string;
  fetchImpl?: typeof fetch;
  now?: () => number;
  maxAgeSeconds?: number;
};

export type CloudRelayJwksCache = Readonly<{
  getKey(kid: string): Promise<CryptoKey>;
  maxAgeSeconds: number;
}>;

const validateJwksUrl = (value: unknown) => {
  if (typeof value !== "string") {
    cloudRelayTicketError(
      "INVALID_VERIFIER_CONFIG",
      "Trusted Cloud Auth JWKS URL must be configured explicitly",
    );
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    cloudRelayTicketError(
      "INVALID_VERIFIER_CONFIG",
      "Trusted Cloud Auth JWKS URL is malformed",
    );
  }

  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    cloudRelayTicketError(
      "INVALID_VERIFIER_CONFIG",
      "Trusted Cloud Auth JWKS URL must be a plain HTTPS URL",
    );
  }

  return url.toString();
};

const validateMaxAge = (value: number) => {
  if (!Number.isInteger(value) || value <= 0 || value > CLOUD_AUTH_JWKS_CACHE_SECONDS) {
    cloudRelayTicketError(
      "INVALID_VERIFIER_CONFIG",
      `JWKS max age must be an integer between 1 and ${CLOUD_AUTH_JWKS_CACHE_SECONDS} seconds`,
    );
  }
  return value;
};

const readBoundedBody = async (response: Response): Promise<string> => {
  const body = response.body;
  if (body === null) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > CLOUD_AUTH_JWKS_MAX_BYTES) {
      cloudRelayTicketError("JWKS_INVALID", "Trusted Cloud Auth JWKS is too large");
    }
    return text;
  }

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > CLOUD_AUTH_JWKS_MAX_BYTES) {
        await reader.cancel().catch(() => undefined);
        cloudRelayTicketError("JWKS_INVALID", "Trusted Cloud Auth JWKS is too large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
};

const parseTrustedKeys = async (value: unknown) => {
  if (!isRecord(value) || !Object.hasOwn(value, "keys")) {
    cloudRelayTicketError("JWKS_INVALID", "Trusted Cloud Auth JWKS is malformed");
  }
  if (Object.keys(value).length !== 1 || !Array.isArray(value.keys)) {
    cloudRelayTicketError("JWKS_INVALID", "Trusted Cloud Auth JWKS is malformed");
  }
  if (value.keys.length === 0 || value.keys.length > CLOUD_AUTH_JWKS_MAX_KEYS) {
    cloudRelayTicketError("JWKS_INVALID", "Trusted Cloud Auth JWKS key count is invalid");
  }

  const keys = new Map<string, TrustedKey>();
  for (const entry of value.keys) {
    if (!isRecord(entry) || Object.keys(entry).length !== JWK_FIELDS.length) {
      cloudRelayTicketError("JWKS_INVALID", "Trusted Cloud Auth JWKS key entry is malformed");
    }
    const fields = Object.keys(entry);
    if (fields.some((field) => !(JWK_FIELDS as readonly string[]).includes(field))) {
      cloudRelayTicketError("JWKS_INVALID", "Trusted Cloud Auth JWKS key entry is malformed");
    }
    if (
      entry.kty !== "OKP" ||
      entry.crv !== "Ed25519" ||
      entry.use !== "sig" ||
      entry.alg !== "EdDSA" ||
      !isCloudAuthKeyId(entry.kid) ||
      typeof entry.x !== "string" ||
      !ED25519_JWK_X_PATTERN.test(entry.x)
    ) {
      cloudRelayTicketError("JWKS_INVALID", "Trusted Cloud Auth JWKS key entry is invalid");
    }
    if (keys.has(entry.kid)) {
      cloudRelayTicketError("JWKS_INVALID", "Trusted Cloud Auth JWKS contains duplicate key ids");
    }

    let publicKey: CryptoKey;
    try {
      publicKey = await importJWK(
        { kty: "OKP", crv: "Ed25519", x: entry.x },
        "EdDSA",
      );
    } catch {
      cloudRelayTicketError("JWKS_INVALID", "Trusted Cloud Auth JWKS key could not be imported");
    }

    keys.set(entry.kid, { publicKey });
  }

  return keys;
};

export function createCloudRelayJwksCache(
  options: CloudRelayJwksCacheOptions,
): CloudRelayJwksCache {
  const jwksUrl = validateJwksUrl(options.jwksUrl);
  const maxAgeSeconds = validateMaxAge(
    options.maxAgeSeconds ?? CLOUD_AUTH_JWKS_CACHE_SECONDS,
  );
  const maxAgeMs = maxAgeSeconds * 1000;
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? Date.now;

  let snapshot: JwksSnapshot | null = null;
  let inFlight: Promise<JwksSnapshot> | null = null;

  const readNow = () => {
    const value = now();
    if (!Number.isFinite(value)) {
      cloudRelayTicketError("INVALID_VERIFIER_CONFIG", "Verifier clock must provide a valid time");
    }
    return value;
  };

  const refresh = async (): Promise<JwksSnapshot> => {
    let response: Response;
    try {
      response = await fetchImpl(jwksUrl, {
        method: "GET",
        headers: { accept: "application/jwk-set+json, application/json" },
        redirect: "error",
        cache: "no-store",
      });
    } catch {
      cloudRelayTicketError("JWKS_UNAVAILABLE", "Trusted Cloud Auth JWKS is unavailable");
    }

    if (!response.ok) {
      cloudRelayTicketError("JWKS_UNAVAILABLE", "Trusted Cloud Auth JWKS is unavailable");
    }

    let body: string;
    try {
      body = await readBoundedBody(response);
    } catch (error) {
      if (error instanceof CloudRelayTicketVerificationError) throw error;
      cloudRelayTicketError("JWKS_UNAVAILABLE", "Trusted Cloud Auth JWKS is unavailable");
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(body) as unknown;
    } catch {
      cloudRelayTicketError("JWKS_INVALID", "Trusted Cloud Auth JWKS is not valid JSON");
    }

    const keys = await parseTrustedKeys(parsed);
    return { keys, fetchedAtMs: readNow() };
  };

  const currentSnapshot = async () => {
    const current = snapshot;
    const observedNow = readNow();
    if (current !== null && observedNow - current.fetchedAtMs < maxAgeMs) {
      return current;
    }

    if (inFlight === null) {
      inFlight = refresh()
        .then((next) => {
          snapshot = next;
          return next;
        })
        .finally(() => {
          inFlight = null;
        });
    }
    return inFlight;
  };

  return {
    maxAgeSeconds,
    async getKey(kid) {
      const current = await currentSnapshot();
      const trusted = current.keys.get(kid);
      if (trusted === undefined) {
        cloudRelayTicketError("UNKNOWN_KEY", "Relay ticket key id is not trusted");
      }
      return trusted.publicKey;
    },
  };
}
