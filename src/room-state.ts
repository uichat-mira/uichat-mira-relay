import { PROTOCOL_VERSION, isRecord } from "./protocol.js";

export type RelayRole = "host" | "client";

/** Derived only from a verified Cloud Relay ticket, never from a client frame. */
export type CloudClientIdentity = Readonly<{
  accountId: string;
  deviceId: string;
  room: string;
  role: "client";
}>;

export type RelayAttachment = {
  authenticated: boolean;
  connectionId: string;
  relayId: string;
  role?: RelayRole;
  activeRequestIds: string[];
  replaced?: boolean;
  /** During asynchronous Cloud JWKS verification, reject any second frame. */
  admissionPending?: boolean;
  admissionRejected?: boolean;
  /** Verified Cloud identity retained for Cloud-only Client forwarding. */
  cloudClientIdentity?: CloudClientIdentity;
};

const MAX_IDENTITY_VALUE_LENGTH = 128;

const isBoundedNonEmptyString = (value: unknown): value is string =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= MAX_IDENTITY_VALUE_LENGTH;

export const isCloudClientIdentity = (
  value: unknown,
): value is CloudClientIdentity => {
  if (!isRecord(value) || value.role !== "client") return false;
  return (
    isBoundedNonEmptyString(value.accountId) &&
    isBoundedNonEmptyString(value.deviceId) &&
    isBoundedNonEmptyString(value.room)
  );
};


export const sha256Hex = async (value: string) => {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
};

export const readAttachment = (socket: WebSocket): RelayAttachment | null => {
  const value = socket.deserializeAttachment();
  if (!isRecord(value)) return null;
  if (
    typeof value.authenticated !== "boolean" ||
    typeof value.connectionId !== "string" ||
    typeof value.relayId !== "string" ||
    !Array.isArray(value.activeRequestIds)
  ) {
    return null;
  }

  const role = value.role;
  if (role !== undefined && role !== "host" && role !== "client") {
    return null;
  }

  const cloudClientIdentity = value.cloudClientIdentity;

  return {
    authenticated: value.authenticated,
    connectionId: value.connectionId,
    relayId: value.relayId,
    ...(role ? { role } : {}),
    activeRequestIds: value.activeRequestIds.filter(
      (item): item is string => typeof item === "string",
    ),
    ...(value.replaced === true ? { replaced: true } : {}),
    ...(value.admissionPending === true ? { admissionPending: true } : {}),
    ...(value.admissionRejected === true ? { admissionRejected: true } : {}),
    ...(isCloudClientIdentity(cloudClientIdentity)
      ? { cloudClientIdentity }
      : {}),
  };
};

export const writeAttachment = (socket: WebSocket, value: RelayAttachment) => {
  socket.serializeAttachment(value);
};

export const safeSend = (socket: WebSocket, frame: Record<string, unknown>) => {
  try {
    socket.send(JSON.stringify({ version: PROTOCOL_VERSION, ...frame }));
    return true;
  } catch {
    return false;
  }
};

