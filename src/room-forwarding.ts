import {
  requestIdFrom, internalRequestId, parseInternalRequestId, type RelayFrame,
} from "./protocol.js";
import { buildCloudForwardedFrame } from "./cloud-provenance.js";
import {
  isCloudClientIdentity, readAttachment, writeAttachment, safeSend,
  type CloudClientIdentity, type RelayAttachment,
} from "./room-state.js";
import { removeActiveRequest } from "./room-sockets.js";

const MAX_ACTIVE_REQUESTS_PER_CLIENT = 32;

export type ForwardPort = {
  hostSockets(): WebSocket[];
  clientSockets(): WebSocket[];
  failSocket(socket: WebSocket, code: string, message: string): void;
};

/** Cloud-only Client forwarding. Fails closed without verified ticket identity. */
export function handleCloudClientFrame(
  room: ForwardPort,
  socket: WebSocket,
  attachment: RelayAttachment,
  frame: RelayFrame,
) {
  const identity = attachment.cloudClientIdentity;
  if (
    !isCloudClientIdentity(identity) ||
    attachment.role !== "client" ||
    identity.room !== attachment.relayId
  ) {
    room.failSocket(
      socket,
      "CLOUD_CLIENT_IDENTITY_UNAVAILABLE",
      "Verified Cloud client identity is unavailable",
    );
    return;
  }

  forwardClientFrame(room, socket, attachment, frame, identity);
}

export function handleClientFrame(
  room: ForwardPort,
    socket: WebSocket,
    attachment: RelayAttachment,
    frame: RelayFrame,
  ) {
    forwardClientFrame(room, socket, attachment, frame);
}

function forwardClientFrame(
  room: ForwardPort,
  socket: WebSocket,
  attachment: RelayAttachment,
  frame: RelayFrame,
  cloudIdentity?: CloudClientIdentity,
) {
    if (frame.type !== "request" && frame.type !== "cancel") {
      room.failSocket(
        socket,
        "CLIENT_FRAME_NOT_ALLOWED",
        "Client relay connections may only send request or cancel frames",
      );
      return;
    }

    const requestId = requestIdFrom(frame);
    if (!requestId) {
      safeSend(socket, {
        type: "error",
        code: "INVALID_REQUEST_ID",
        message: "Relay request id is invalid",
        retryable: false,
      });
      return;
    }

    const host = room.hostSockets()[0];
    if (!host) {
      safeSend(socket, {
        type: "error",
        requestId,
        code: "HOST_OFFLINE",
        message: "Mira Desktop Relay host is offline",
        retryable: true,
      });
      return;
    }

    const forwardedFrame = (clientRequestId: string) => {
      const routedRequestId = internalRequestId(
        attachment.connectionId,
        clientRequestId,
      );
      return cloudIdentity
        ? buildCloudForwardedFrame(
            frame,
            cloudIdentity,
            attachment.connectionId,
            routedRequestId,
          )
        : { ...frame, requestId: routedRequestId };
    };

    if (frame.type === "cancel") {
      if (!attachment.activeRequestIds.includes(requestId)) return;
      removeActiveRequest(socket, attachment, requestId);
      safeSend(host, forwardedFrame(requestId));
      return;
    }

    if (attachment.activeRequestIds.includes(requestId)) {
      safeSend(socket, {
        type: "error",
        requestId,
        code: "REQUEST_ID_IN_USE",
        message: "Relay request id is already active",
        retryable: false,
      });
      return;
    }

    if (attachment.activeRequestIds.length >= MAX_ACTIVE_REQUESTS_PER_CLIENT) {
      safeSend(socket, {
        type: "error",
        requestId,
        code: "TOO_MANY_ACTIVE_REQUESTS",
        message: "Too many relay requests are active on this connection",
        retryable: true,
      });
      return;
    }

    writeAttachment(socket, {
      ...attachment,
      activeRequestIds: [...attachment.activeRequestIds, requestId],
    });
    safeSend(host, forwardedFrame(requestId));
}
export function handleHostFrame(
  room: ForwardPort,socket: WebSocket, frame: RelayFrame) {
    if (
      frame.type !== "response" &&
      frame.type !== "chunk" &&
      frame.type !== "complete" &&
      frame.type !== "error"
    ) {
      room.failSocket(
        socket,
        "HOST_FRAME_NOT_ALLOWED",
        "Host relay connections may only send response, chunk, complete or error frames",
      );
      return;
    }

    if (frame.type === "error" && frame.requestId === undefined) {
      for (const client of room.clientSockets()) safeSend(client, frame);
      return;
    }

    const routed = parseInternalRequestId(frame.requestId);
    if (!routed) {
      safeSend(socket, {
        type: "error",
        code: "INVALID_ROUTED_REQUEST_ID",
        message: "Host response does not contain a valid routed request id",
        retryable: false,
      });
      return;
    }

    const client = room.clientSockets().find((candidate) => {
      const candidateAttachment = readAttachment(candidate);
      return candidateAttachment?.connectionId === routed.connectionId;
    });
    if (!client) {
      if (frame.type !== "complete" && frame.type !== "error") {
        safeSend(socket, { type: "cancel", requestId: String(frame.requestId) });
      }
      return;
    }

    const clientAttachment = readAttachment(client);
    if (
      !clientAttachment ||
      !clientAttachment.activeRequestIds.includes(routed.requestId)
    ) {
      if (frame.type !== "complete" && frame.type !== "error") {
        safeSend(socket, { type: "cancel", requestId: String(frame.requestId) });
      }
      return;
    }

    safeSend(client, { ...frame, requestId: routed.requestId });
    if (frame.type === "complete" || frame.type === "error") {
      removeActiveRequest(client, clientAttachment, routed.requestId);
    }
}