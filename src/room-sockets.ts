import { PROTOCOL_VERSION, internalRequestId } from "./protocol.js";
import { readAttachment, writeAttachment, safeSend, type RelayAttachment } from "./room-state.js";

export function failAllClientRequests(
  ctx: DurableObjectState,code: string, message: string) {
    for (const client of clientSockets(ctx)) {
      const attachment = readAttachment(client);
      if (!attachment) continue;

      for (const requestId of attachment.activeRequestIds) {
        safeSend(client, {
          type: "error",
          requestId,
          code,
          message,
          retryable: true,
        });
      }
      writeAttachment(client, { ...attachment, activeRequestIds: [] });
    }
}
export function removeActiveRequest(
    socket: WebSocket,
    attachment: RelayAttachment,
    requestId: string,
  ) {
    if (!attachment.activeRequestIds.includes(requestId)) return;
    writeAttachment(socket, {
      ...attachment,
      activeRequestIds: attachment.activeRequestIds.filter(
        (activeId) => activeId !== requestId,
      ),
    });
}
export function hostSockets(ctx: DurableObjectState) {
    return ctx.getWebSockets().filter((socket) => {
      const attachment = readAttachment(socket);
      return (
        attachment?.authenticated === true &&
        attachment.role === "host" &&
        attachment.replaced !== true
      );
    });
}
export function clientSockets(ctx: DurableObjectState) {
    return ctx.getWebSockets().filter((socket) => {
      const attachment = readAttachment(socket);
      return attachment?.authenticated === true && attachment.role === "client";
    });
}
export function cleanupSocket(
  ctx: DurableObjectState,socket: WebSocket) {
    const attachment = readAttachment(socket);
    if (!attachment?.authenticated) return;

    if (attachment.role === "client") {
      const host = hostSockets(ctx)[0];
      if (host) {
        for (const requestId of attachment.activeRequestIds) {
          safeSend(host, {
            type: "cancel",
            requestId: internalRequestId(attachment.connectionId, requestId),
          });
        }
      }
      return;
    }

    if (attachment.role === "host" && attachment.replaced !== true) {
      failAllClientRequests(ctx, 
        "HOST_DISCONNECTED",
        "Mira Desktop Relay host disconnected",
      );
      for (const client of clientSockets(ctx)) {
        safeSend(client, {
          type: "error",
          code: "HOST_DISCONNECTED",
          message: "Mira Desktop Relay host disconnected",
          retryable: true,
        });
      }
    }
}
export function failSocket(socket: WebSocket, code: string, message: string) {
    safeSend(socket, {
      type: "error",
      code,
      message,
      retryable: false,
    });
    try {
      socket.close(1008, message.slice(0, 100));
    } catch {
      // Socket may already be closed.
    }
}