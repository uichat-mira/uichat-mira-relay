import { isRecord } from "./protocol.js";
import type { CloudClientIdentity } from "./room-state.js";

export const RELAY_PROVENANCE_FIELD = "relayProvenance";
export const RELAY_PROVENANCE_VERSION = 1;

/**
 * Transport identity metadata that a Cloud Client must never supply itself.
 * Matching keys are removed at any depth before the Host-directed frame is sent.
 */
const RESERVED_IDENTITY_FIELDS = new Set([
  RELAY_PROVENANCE_FIELD,
  "provenance",
  "identity",
  "caller",
  "callerIdentity",
  "mobileDeviceId",
  "mobileDeviceIdentity",
  "accountId",
  "deviceId",
]);

export type RelayClientProvenance = Readonly<{
  version: typeof RELAY_PROVENANCE_VERSION;
  transport: "cloud";
  accountId: string;
  deviceId: string;
  room: string;
  role: "client";
  connectionId: string;
  requestId: string;
}>;

const stripIdentityMarkers = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(stripIdentityMarkers);
  if (!isRecord(value)) return value;

  const stripped: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    if (RESERVED_IDENTITY_FIELDS.has(key)) continue;
    stripped[key] = stripIdentityMarkers(child);
  }
  return stripped;
};

/**
 * Build the Cloud Host-directed frame from the Client frame. Any Client-supplied
 * identity marker is removed; `relayProvenance` is authored only from the
 * verified WebSocket ticket and the rewritten room-scoped request id.
 */
export function buildCloudForwardedFrame(
  frame: Record<string, unknown>,
  identity: CloudClientIdentity,
  connectionId: string,
  requestId: string,
): Record<string, unknown> {
  const stripped = stripIdentityMarkers(frame) as Record<string, unknown>;
  const provenance: RelayClientProvenance = Object.freeze({
    version: RELAY_PROVENANCE_VERSION,
    transport: "cloud",
    accountId: identity.accountId,
    deviceId: identity.deviceId,
    room: identity.room,
    role: "client",
    connectionId,
    requestId,
  });

  return {
    ...stripped,
    requestId,
    [RELAY_PROVENANCE_FIELD]: provenance,
  };
}
