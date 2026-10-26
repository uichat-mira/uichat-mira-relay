// Pure Relay V1 frame/room validation. Deliberately contains no Cloud auth.
export const PROTOCOL_VERSION = 1;
export const MAX_FRAME_CHARS = 2 * 1024 * 1024;
export const RELAY_ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/u;
export const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{1,160}$/u;
export const TOKEN_MIN_LENGTH = 32;
export const TOKEN_MAX_LENGTH = 512;

export type RelayFrame = Record<string, unknown> & {
  version: number;
  type: string;
};

export const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export const parseRelayId = (pathname: string) => {
  const matched = pathname.match(
    /^\/v1\/relay\/([A-Za-z0-9_-]{16,128})\/socket$/u,
  );
  return matched?.[1] ?? null;
};

export const isWebSocketUpgrade = (request: Request) =>
  request.headers.get("Upgrade")?.toLowerCase() === "websocket";

export const parseFrame = (message: string): RelayFrame | null => {
  if (message.length > MAX_FRAME_CHARS) return null;

  try {
    const parsed = JSON.parse(message) as unknown;
    if (
      !isRecord(parsed) ||
      parsed.version !== PROTOCOL_VERSION ||
      typeof parsed.type !== "string"
    ) {
      return null;
    }
    return parsed as RelayFrame;
  } catch {
    return null;
  }
};

export const normalizeToken = (value: unknown) => {
  if (typeof value !== "string") return null;
  const normalized = value.trim();
  if (
    normalized.length < TOKEN_MIN_LENGTH ||
    normalized.length > TOKEN_MAX_LENGTH
  ) {
    return null;
  }
  return normalized;
};

export const requestIdFrom = (frame: RelayFrame) =>
  typeof frame.requestId === "string" && REQUEST_ID_PATTERN.test(frame.requestId)
    ? frame.requestId
    : null;

export const internalRequestId = (connectionId: string, requestId: string) =>
  `${connectionId}~${requestId}`;

export const parseInternalRequestId = (value: unknown) => {
  if (typeof value !== "string") return null;
  const separator = value.indexOf("~");
  if (separator <= 0 || separator === value.length - 1) return null;

  const connectionId = value.slice(0, separator);
  const requestId = value.slice(separator + 1);
  if (!REQUEST_ID_PATTERN.test(requestId)) return null;
  return { connectionId, requestId };
};

