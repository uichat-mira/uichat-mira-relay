import { CloudRelayTicketVerificationError, type CloudRelayTicketIdentity } from "./cloud-relay-ticket.js";
import { admitClient, admitHost, type AdmissionPort } from "./room-admission.js";
import type { RelayFrame } from "./protocol.js";
import { readAttachment, writeAttachment, type RelayAttachment } from "./room-state.js";

export type CloudAdmissionPort = AdmissionPort & {
  verifyCloudTicket(
    token: string,
    expected: { room: string; role: "host" | "client" },
  ): Promise<CloudRelayTicketIdentity>;
};

const reject = (port: CloudAdmissionPort, socket: WebSocket, code: string) => {
  const current = readAttachment(socket);
  if (current) writeAttachment(socket, { ...current, admissionPending: false, admissionRejected: true });
  port.failSocket(socket, code, "Cloud Relay connection admission denied");
};

/** First-frame-only Cloud admission. Never calls Legacy token/hash provisioning. */
export async function handleCloudHello(
  port: CloudAdmissionPort,
  socket: WebSocket,
  attachment: RelayAttachment,
  frame: RelayFrame,
): Promise<void> {
  if (frame.type !== "hello") {
    reject(port, socket, "HELLO_REQUIRED");
    return;
  }
  if (
    (frame.role !== "host" && frame.role !== "client") ||
    frame.relayId !== attachment.relayId
  ) {
    reject(port, socket, "CLOUD_INVALID_HELLO");
    return;
  }
  if (Object.hasOwn(frame, "clientToken")) {
    reject(port, socket, "CLOUD_LEGACY_PROVISION_FORBIDDEN");
    return;
  }
  if (typeof frame.token !== "string" || frame.token.length === 0) {
    reject(port, socket, "CLOUD_TICKET_REQUIRED");
    return;
  }

  // Mark before awaiting JWKS: a concurrent second frame must not be
  // forwarded or allowed to authenticate a socket being rejected.
  writeAttachment(socket, { ...attachment, admissionPending: true });
  let identity: CloudRelayTicketIdentity;
  try {
    identity = await port.verifyCloudTicket(frame.token, {
      room: attachment.relayId,
      role: frame.role,
    });
  } catch (error) {
    const unavailable =
      error instanceof CloudRelayTicketVerificationError &&
      (error.code === "JWKS_UNAVAILABLE" ||
        error.code === "JWKS_INVALID" ||
        error.code === "INVALID_VERIFIER_CONFIG");
    reject(port, socket, unavailable ? "CLOUD_AUTH_UNAVAILABLE" : "CLOUD_TICKET_REJECTED");
    return;
  }

  if (identity.room !== attachment.relayId || identity.role !== frame.role) {
    reject(port, socket, "CLOUD_TICKET_REJECTED");
    return;
  }

  const current = readAttachment(socket);
  if (
    current?.admissionPending !== true ||
    current.admissionRejected === true ||
    current.authenticated ||
    socket.readyState !== WebSocket.OPEN
  ) return;

  const accepted = { ...current, admissionPending: false };
  if (frame.role === "host") {
    admitHost(port, socket, accepted);
    return;
  }

  admitClient(port, socket, {
    ...accepted,
    cloudClientIdentity: {
      accountId: identity.accountId,
      deviceId: identity.deviceId,
      room: identity.room,
      role: "client",
    },
  });
}
