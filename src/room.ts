import { DurableObject } from "cloudflare:workers";
import { PROTOCOL_VERSION, RELAY_ID_PATTERN, parseRelayId, isWebSocketUpgrade, parseFrame } from "./protocol.js";
import { readAttachment, writeAttachment, safeSend } from "./room-state.js";
import { handleHello, type AdmissionPort } from "./room-admission.js";
import { handleClientFrame, handleHostFrame, type ForwardPort } from "./room-forwarding.js";
import { hostSockets, clientSockets, failAllClientRequests, cleanupSocket, failSocket } from "./room-sockets.js";
import { json, type Env } from "./worker.js";

export class RelayRoom extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS relay_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      )
    `);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const relayId = parseRelayId(url.pathname);
    if (!relayId || !RELAY_ID_PATTERN.test(relayId)) {
      return json({ error: "invalid_relay_id" }, 404);
    }
    if (!isWebSocketUpgrade(request)) {
      return json({ error: "websocket_required" }, 426);
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.ctx.acceptWebSocket(server);
    writeAttachment(server, {
      authenticated: false,
      connectionId: crypto.randomUUID(),
      relayId,
      activeRequestIds: [],
    });

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(
    socket: WebSocket,
    message: string | ArrayBuffer,
  ): Promise<void> {
    if (typeof message !== "string") {
      failSocket(
        socket,
        "BINARY_FRAME_UNSUPPORTED",
        "Binary relay frames are not supported",
      );
      return;
    }

    const frame = parseFrame(message);
    if (!frame) {
      failSocket(
        socket,
        "INVALID_FRAME",
        "Relay frame is invalid or too large",
      );
      return;
    }

    const attachment = readAttachment(socket);
    if (!attachment) {
      failSocket(
        socket,
        "INVALID_CONNECTION_STATE",
        "Relay connection state is invalid",
      );
      return;
    }

    if (!attachment.authenticated) {
      await handleHello(this.admissionPort(), socket, attachment, frame);
      return;
    }

    if (frame.type === "hello") {
      failSocket(
        socket,
        "HELLO_ALREADY_COMPLETED",
        "Relay hello has already completed",
      );
      return;
    }

    if (attachment.role === "client") {
      handleClientFrame(this.forwardPort(), socket, attachment, frame);
      return;
    }

    if (attachment.role === "host") {
      handleHostFrame(this.forwardPort(), socket, frame);
      return;
    }

    failSocket(socket, "INVALID_ROLE", "Relay connection role is invalid");
  }

  webSocketClose(
    socket: WebSocket,
    _code: number,
    _reason: string,
    _wasClean: boolean,
  ) {
    cleanupSocket(this.ctx, socket);
  }

  webSocketError(socket: WebSocket, _error: unknown) {
    cleanupSocket(this.ctx, socket);
  }

  private readConfig(key: string) {
    const row = this.ctx.storage.sql
      .exec<{ value: string }>(
        "SELECT value FROM relay_config WHERE key = ? LIMIT 1",
        key,
      )
      .toArray()[0];
    return row?.value ?? null;
  }

  private writeConfig(key: string, value: string) {
    this.ctx.storage.sql.exec(
      `INSERT INTO relay_config (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
      key,
      value,
    );
  }


  private admissionPort(): AdmissionPort {
    return {
      readConfig: (key) => this.readConfig(key),
      writeConfig: (key, value) => this.writeConfig(key, value),
      hostSockets: () => hostSockets(this.ctx),
      failAllClientRequests: (code, message) =>
        failAllClientRequests(this.ctx, code, message),
      failSocket,
    };
  }

  private forwardPort(): ForwardPort {
    return {
      hostSockets: () => hostSockets(this.ctx),
      clientSockets: () => clientSockets(this.ctx),
      failSocket,
    };
  }
}
