import { PROTOCOL_VERSION, normalizeToken, type RelayFrame } from "./protocol.js";
import {
  readAttachment, writeAttachment, safeSend, sha256Hex, type RelayAttachment,
} from "./room-state.js";

export type AdmissionPort = {
  readConfig(key: string): string | null;
  writeConfig(key: string, value: string): void;
  hostSockets(): WebSocket[];
  failAllClientRequests(code: string, message: string): void;
  failSocket(socket: WebSocket, code: string, message: string): void;
};

export async function handleHello(
  room: AdmissionPort,
    socket: WebSocket,
    attachment: RelayAttachment,
    frame: RelayFrame,
  ) {
    if (frame.type !== "hello") {
      room.failSocket(socket, "HELLO_REQUIRED", "First relay frame must be hello");
      return;
    }

    if (
      (frame.role !== "host" && frame.role !== "client") ||
      frame.relayId !== attachment.relayId
    ) {
      room.failSocket(
        socket,
        "INVALID_HELLO",
        "Relay hello role or relay id is invalid",
      );
      return;
    }

    if (frame.role === "host") {
      await authenticateHost(room, socket, attachment, frame);
      return;
    }

    await authenticateClient(room, socket, attachment, frame);
}
async function authenticateHost(
  room: AdmissionPort,
    socket: WebSocket,
    attachment: RelayAttachment,
    frame: RelayFrame,
  ) {
    const token = normalizeToken(frame.token);
    if (!token) {
      room.failSocket(
        socket,
        "HOST_AUTH_REQUIRED",
        "A valid host relay token is required",
      );
      return;
    }

    const hostHash = await sha256Hex(token);
    const configuredHostHash = room.readConfig("host_token_hash");

    if (!configuredHostHash) {
      const clientToken = normalizeToken(frame.clientToken);
      if (!clientToken) {
        room.failSocket(
          socket,
          "CLIENT_TOKEN_REQUIRED",
          "The first host connection must provision a client relay token",
        );
        return;
      }
      room.writeConfig("host_token_hash", hostHash);
      room.writeConfig("client_token_hash", await sha256Hex(clientToken));
    } else if (configuredHostHash !== hostHash) {
      room.failSocket(socket, "HOST_AUTH_FAILED", "Host relay token is invalid");
      return;
    } else if (frame.clientToken !== undefined) {
      const clientToken = normalizeToken(frame.clientToken);
      const configuredClientHash = room.readConfig("client_token_hash");
      if (
        !clientToken ||
        !configuredClientHash ||
        configuredClientHash !== (await sha256Hex(clientToken))
      ) {
        room.failSocket(
          socket,
          "CLIENT_TOKEN_MISMATCH",
          "Configured client relay token does not match this relay room",
        );
        return;
      }
    }

    const existingHosts = room.hostSockets().filter((existing) => existing !== socket);
    if (existingHosts.length) {
      room.failAllClientRequests(
        "HOST_REPLACED",
        "Mira Desktop Relay host connection was replaced",
      );
      for (const existing of existingHosts) {
        const existingAttachment = readAttachment(existing);
        if (existingAttachment) {
          writeAttachment(existing, { ...existingAttachment, replaced: true });
        }
        existing.close(1012, "Mira Relay host replaced");
      }
    }

    writeAttachment(socket, {
      ...attachment,
      authenticated: true,
      role: "host",
      activeRequestIds: [],
    });
    safeSend(socket, {
      type: "hello_ack",
      role: "host",
      relayId: attachment.relayId,
      protocolVersion: PROTOCOL_VERSION,
    });
}
async function authenticateClient(
  room: AdmissionPort,
    socket: WebSocket,
    attachment: RelayAttachment,
    frame: RelayFrame,
  ) {
    const token = normalizeToken(frame.token);
    const configuredClientHash = room.readConfig("client_token_hash");
    if (
      !token ||
      !configuredClientHash ||
      configuredClientHash !== (await sha256Hex(token))
    ) {
      room.failSocket(
        socket,
        "CLIENT_AUTH_FAILED",
        "Client relay token is invalid",
      );
      return;
    }

    writeAttachment(socket, {
      ...attachment,
      authenticated: true,
      role: "client",
      activeRequestIds: [],
    });
    safeSend(socket, {
      type: "hello_ack",
      role: "client",
      relayId: attachment.relayId,
      protocolVersion: PROTOCOL_VERSION,
      hostConnected: room.hostSockets().length > 0,
    });
}