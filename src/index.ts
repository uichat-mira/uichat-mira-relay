import { DurableObject } from "cloudflare:workers";

const PROTOCOL_VERSION = 1;
const MAX_FRAME_CHARS = 2 * 1024 * 1024;
const MAX_ACTIVE_REQUESTS_PER_CLIENT = 32;
const RELAY_ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/u;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{1,160}$/u;
const TOKEN_MIN_LENGTH = 32;
const TOKEN_MAX_LENGTH = 512;

type RelayRole = "host" | "client";

type RelayAttachment = {
  authenticated: boolean;
  connectionId: string;
  relayId: string;
  role?: RelayRole;
  activeRequestIds: string[];
  replaced?: boolean;
};

type RelayFrame = Record<string, unknown> & {
  version: number;
  type: string;
};

type Env = {
  RELAY_ROOMS: DurableObjectNamespace;
};

const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const parseRelayId = (pathname: string) => {
  const matched = pathname.match(
    /^\/v1\/relay\/([A-Za-z0-9_-]{16,128})\/socket$/u,
  );
  return matched?.[1] ?? null;
};

const isWebSocketUpgrade = (request: Request) =>
  request.headers.get("Upgrade")?.toLowerCase() === "websocket";

const parseFrame = (message: string): RelayFrame | null => {
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

const normalizeToken = (value: unknown) => {
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

const sha256Hex = async (value: string) => {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
};

const readAttachment = (socket: WebSocket): RelayAttachment | null => {
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
  };
};

const writeAttachment = (socket: WebSocket, value: RelayAttachment) => {
  socket.serializeAttachment(value);
};

const safeSend = (socket: WebSocket, frame: Record<string, unknown>) => {
  try {
    socket.send(JSON.stringify({ version: PROTOCOL_VERSION, ...frame }));
    return true;
  } catch {
    return false;
  }
};

const requestIdFrom = (frame: RelayFrame) =>
  typeof frame.requestId === "string" && REQUEST_ID_PATTERN.test(frame.requestId)
    ? frame.requestId
    : null;

const internalRequestId = (connectionId: string, requestId: string) =>
  `${connectionId}~${requestId}`;

const parseInternalRequestId = (value: unknown) => {
  if (typeof value !== "string") return null;
  const separator = value.indexOf("~");
  if (separator <= 0 || separator === value.length - 1) return null;

  const connectionId = value.slice(0, separator);
  const requestId = value.slice(separator + 1);
  if (!REQUEST_ID_PATTERN.test(requestId)) return null;
  return { connectionId, requestId };
};

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
      this.failSocket(
        socket,
        "BINARY_FRAME_UNSUPPORTED",
        "Binary relay frames are not supported",
      );
      return;
    }

    const frame = parseFrame(message);
    if (!frame) {
      this.failSocket(
        socket,
        "INVALID_FRAME",
        "Relay frame is invalid or too large",
      );
      return;
    }

    const attachment = readAttachment(socket);
    if (!attachment) {
      this.failSocket(
        socket,
        "INVALID_CONNECTION_STATE",
        "Relay connection state is invalid",
      );
      return;
    }

    if (!attachment.authenticated) {
      await this.handleHello(socket, attachment, frame);
      return;
    }

    if (frame.type === "hello") {
      this.failSocket(
        socket,
        "HELLO_ALREADY_COMPLETED",
        "Relay hello has already completed",
      );
      return;
    }

    if (attachment.role === "client") {
      this.handleClientFrame(socket, attachment, frame);
      return;
    }

    if (attachment.role === "host") {
      this.handleHostFrame(socket, frame);
      return;
    }

    this.failSocket(socket, "INVALID_ROLE", "Relay connection role is invalid");
  }

  webSocketClose(
    socket: WebSocket,
    _code: number,
    _reason: string,
    _wasClean: boolean,
  ) {
    this.cleanupSocket(socket);
  }

  webSocketError(socket: WebSocket, _error: unknown) {
    this.cleanupSocket(socket);
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

  private async handleHello(
    socket: WebSocket,
    attachment: RelayAttachment,
    frame: RelayFrame,
  ) {
    if (frame.type !== "hello") {
      this.failSocket(socket, "HELLO_REQUIRED", "First relay frame must be hello");
      return;
    }

    if (
      (frame.role !== "host" && frame.role !== "client") ||
      frame.relayId !== attachment.relayId
    ) {
      this.failSocket(
        socket,
        "INVALID_HELLO",
        "Relay hello role or relay id is invalid",
      );
      return;
    }

    if (frame.role === "host") {
      await this.authenticateHost(socket, attachment, frame);
      return;
    }

    await this.authenticateClient(socket, attachment, frame);
  }

  private async authenticateHost(
    socket: WebSocket,
    attachment: RelayAttachment,
    frame: RelayFrame,
  ) {
    const token = normalizeToken(frame.token);
    if (!token) {
      this.failSocket(
        socket,
        "HOST_AUTH_REQUIRED",
        "A valid host relay token is required",
      );
      return;
    }

    const hostHash = await sha256Hex(token);
    const configuredHostHash = this.readConfig("host_token_hash");

    if (!configuredHostHash) {
      const clientToken = normalizeToken(frame.clientToken);
      if (!clientToken) {
        this.failSocket(
          socket,
          "CLIENT_TOKEN_REQUIRED",
          "The first host connection must provision a client relay token",
        );
        return;
      }
      this.writeConfig("host_token_hash", hostHash);
      this.writeConfig("client_token_hash", await sha256Hex(clientToken));
    } else if (configuredHostHash !== hostHash) {
      this.failSocket(socket, "HOST_AUTH_FAILED", "Host relay token is invalid");
      return;
    } else if (frame.clientToken !== undefined) {
      const clientToken = normalizeToken(frame.clientToken);
      const configuredClientHash = this.readConfig("client_token_hash");
      if (
        !clientToken ||
        !configuredClientHash ||
        configuredClientHash !== (await sha256Hex(clientToken))
      ) {
        this.failSocket(
          socket,
          "CLIENT_TOKEN_MISMATCH",
          "Configured client relay token does not match this relay room",
        );
        return;
      }
    }

    const existingHosts = this.hostSockets().filter((existing) => existing !== socket);
    if (existingHosts.length) {
      this.failAllClientRequests(
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

  private async authenticateClient(
    socket: WebSocket,
    attachment: RelayAttachment,
    frame: RelayFrame,
  ) {
    const token = normalizeToken(frame.token);
    const configuredClientHash = this.readConfig("client_token_hash");
    if (
      !token ||
      !configuredClientHash ||
      configuredClientHash !== (await sha256Hex(token))
    ) {
      this.failSocket(
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
      hostConnected: this.hostSockets().length > 0,
    });
  }

  private handleClientFrame(
    socket: WebSocket,
    attachment: RelayAttachment,
    frame: RelayFrame,
  ) {
    if (frame.type !== "request" && frame.type !== "cancel") {
      this.failSocket(
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

    const host = this.hostSockets()[0];
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

    if (frame.type === "cancel") {
      if (!attachment.activeRequestIds.includes(requestId)) return;
      this.removeActiveRequest(socket, attachment, requestId);
      safeSend(host, {
        ...frame,
        requestId: internalRequestId(attachment.connectionId, requestId),
      });
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
    safeSend(host, {
      ...frame,
      requestId: internalRequestId(attachment.connectionId, requestId),
    });
  }

  private handleHostFrame(socket: WebSocket, frame: RelayFrame) {
    if (
      frame.type !== "response" &&
      frame.type !== "chunk" &&
      frame.type !== "complete" &&
      frame.type !== "error"
    ) {
      this.failSocket(
        socket,
        "HOST_FRAME_NOT_ALLOWED",
        "Host relay connections may only send response, chunk, complete or error frames",
      );
      return;
    }

    if (frame.type === "error" && frame.requestId === undefined) {
      for (const client of this.clientSockets()) safeSend(client, frame);
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

    const client = this.clientSockets().find((candidate) => {
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
      this.removeActiveRequest(client, clientAttachment, routed.requestId);
    }
  }

  private failAllClientRequests(code: string, message: string) {
    for (const client of this.clientSockets()) {
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

  private removeActiveRequest(
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

  private hostSockets() {
    return this.ctx.getWebSockets().filter((socket) => {
      const attachment = readAttachment(socket);
      return (
        attachment?.authenticated === true &&
        attachment.role === "host" &&
        attachment.replaced !== true
      );
    });
  }

  private clientSockets() {
    return this.ctx.getWebSockets().filter((socket) => {
      const attachment = readAttachment(socket);
      return attachment?.authenticated === true && attachment.role === "client";
    });
  }

  private cleanupSocket(socket: WebSocket) {
    const attachment = readAttachment(socket);
    if (!attachment?.authenticated) return;

    if (attachment.role === "client") {
      const host = this.hostSockets()[0];
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
      this.failAllClientRequests(
        "HOST_DISCONNECTED",
        "Mira Desktop Relay host disconnected",
      );
      for (const client of this.clientSockets()) {
        safeSend(client, {
          type: "error",
          code: "HOST_DISCONNECTED",
          message: "Mira Desktop Relay host disconnected",
          retryable: true,
        });
      }
    }
  }

  private failSocket(socket: WebSocket, code: string, message: string) {
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
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return json({
        ok: true,
        service: "mira-remote-relay",
        protocolVersion: PROTOCOL_VERSION,
      });
    }

    const relayId = parseRelayId(url.pathname);
    if (!relayId || !RELAY_ID_PATTERN.test(relayId)) {
      return json({ error: "not_found" }, 404);
    }
    if (!isWebSocketUpgrade(request)) {
      return json({ error: "websocket_required" }, 426);
    }

    const id = env.RELAY_ROOMS.idFromName(relayId);
    return env.RELAY_ROOMS.get(id).fetch(request);
  },
};
