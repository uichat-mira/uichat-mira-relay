export const CLOUD_AUTH_SERVICE_CREDENTIAL_ISSUER = "mira:cloud-auth";
export const CLOUD_RELAY_TRANSPORT_AUDIENCE = "mira:cloud-relay-transport";
export const RELAY_TRANSPORT_SCOPE = "relay:transport";

export const CLOUD_RELAY_TICKET_DEFAULT_TTL_SECONDS = 300;
export const CLOUD_RELAY_TICKET_MAX_TTL_SECONDS = 600;
export const CLOUD_RELAY_TICKET_MAX_LENGTH = 8 * 1024;
export const CLOUD_AUTH_JWKS_CACHE_SECONDS = 300;
export const CLOUD_AUTH_JWKS_MAX_KEYS = 8;
export const CLOUD_AUTH_JWKS_MAX_BYTES = 64 * 1024;
export const CLOUD_RELAY_MAX_CLOCK_SKEW_SECONDS = 60;

export const CLOUD_AUTH_KEY_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/u;
export const CLOUD_RELAY_ROOM_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;

export type CloudRelayTicketRole = "host" | "client";

export type CloudRelayTicketContext = Readonly<{
  room: string;
  role: CloudRelayTicketRole;
}>;

export type CloudRelayTicketIdentity = Readonly<{
  accountId: string;
  deviceId: string;
  room: string;
  role: CloudRelayTicketRole;
  expiresAt: Date;
}>;

export type CloudRelayTicketVerificationErrorCode =
  | "MALFORMED_TOKEN"
  | "INVALID_HEADER"
  | "UNKNOWN_KEY"
  | "INVALID_SIGNATURE"
  | "INVALID_CLAIMS"
  | "ISSUER_MISMATCH"
  | "AUDIENCE_MISMATCH"
  | "IAT_IN_FUTURE"
  | "NOT_YET_VALID"
  | "EXPIRED"
  | "TTL_EXCEEDED"
  | "RELAY_CONTEXT_MISMATCH"
  | "JWKS_UNAVAILABLE"
  | "JWKS_INVALID"
  | "INVALID_VERIFIER_CONFIG";

export class CloudRelayTicketVerificationError extends Error {
  readonly code: CloudRelayTicketVerificationErrorCode;

  constructor(code: CloudRelayTicketVerificationErrorCode, message: string) {
    super(message);
    this.name = "CloudRelayTicketVerificationError";
    this.code = code;
  }
}

export const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export const isCloudRelayTicketRole = (
  value: unknown,
): value is CloudRelayTicketRole => value === "host" || value === "client";

export const isCloudRelayRoom = (value: unknown): value is string =>
  typeof value === "string" && CLOUD_RELAY_ROOM_PATTERN.test(value);

export const isCloudAuthKeyId = (value: unknown): value is string =>
  typeof value === "string" && CLOUD_AUTH_KEY_ID_PATTERN.test(value);

export function cloudRelayTicketError(
  code: CloudRelayTicketVerificationErrorCode,
  message: string,
): never {
  throw new CloudRelayTicketVerificationError(code, message);
}
