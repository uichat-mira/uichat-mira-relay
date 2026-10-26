import { PROTOCOL_VERSION, isRecord } from "./protocol.js";

export type RelayRole = "host" | "client";

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

