import { env, exports } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";

export type RelayFrame = Record<string, unknown>;

export const HOST_TOKEN = "h".repeat(48);
export const CLIENT_TOKEN = "c".repeat(48);

export const roomId = (suffix: string) =>
  `relay_${suffix.padEnd(16, "0")}`.slice(0, 22);

const peers = new Set<RelayPeer>();

const parseFrame = (data: unknown): RelayFrame | null => {
  if (typeof data !== "string") return null;
  try {
    const value = JSON.parse(data) as unknown;
    return typeof value === "object" && value !== null
      ? (value as RelayFrame)
      : null;
  } catch {
    return null;
  }
};

export class RelayPeer {
  readonly socket: WebSocket;
  readonly received: RelayFrame[] = [];
  closed: { code: number; reason: string } | null = null;

  private queue: RelayFrame[] = [];
  private waiters: Array<{ resolve: (frame: RelayFrame) => void; reject: (error: Error) => void }> = [];
  private closeWaiters: Array<() => void> = [];

  constructor(socket: WebSocket) {
    this.socket = socket;
    socket.addEventListener("message", (event: MessageEvent) => {
      const frame = parseFrame(event.data);
      if (!frame) return;
      this.received.push(frame);
      const waiter = this.waiters.shift();
      if (waiter) waiter.resolve(frame);
      else this.queue.push(frame);
    });
    socket.addEventListener("close", (event: CloseEvent) => {
      this.closed = { code: event.code, reason: event.reason };
      for (const waiter of this.waiters.splice(0)) {
        waiter.reject(new Error(`relay socket closed (${event.code})`));
      }
      for (const closeWaiter of this.closeWaiters.splice(0)) closeWaiter();
    });
  }

  send(frame: RelayFrame) {
    this.socket.send(JSON.stringify({ version: 1, ...frame }));
  }

  sendRaw(data: string) {
    this.socket.send(data);
  }

  next(timeoutMs = 2000): Promise<RelayFrame> {
    const queued = this.queue.shift();
    if (queued) return Promise.resolve(queued);

    return new Promise((resolve, reject) => {
      const waiter = {
        resolve: (frame: RelayFrame) => {
          clearTimeout(timer);
          resolve(frame);
        },
        reject: (error: Error) => {
          clearTimeout(timer);
          reject(error);
        },
      };
      const timer = setTimeout(() => {
        const index = this.waiters.indexOf(waiter);
        if (index >= 0) this.waiters.splice(index, 1);
        reject(
          new Error(
            `timed out waiting for relay frame; received=${JSON.stringify(this.received)}`,
          ),
        );
      }, timeoutMs);
      this.waiters.push(waiter);
    });
  }

  async expectClose(timeoutMs = 2000) {
    if (!this.closed) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, timeoutMs);
        this.closeWaiters.push(() => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
    if (!this.closed) throw new Error("relay socket did not close");
    return this.closed;
  }

  async expectSilence(timeoutMs = 150) {
    await new Promise((resolve) => setTimeout(resolve, timeoutMs));
    if (this.queue.length) {
      throw new Error(
        `expected no relay frame, received ${JSON.stringify(this.queue)}`,
      );
    }
  }

  close(code = 1000, reason = "test") {
    try {
      this.socket.close(code, reason);
    } catch {
      // Already closing or closed by the room.
    }
  }
}

export async function connect(relay: string): Promise<RelayPeer> {
  const response = await exports.default.fetch(
    new Request(`https://relay.test/v1/relay/${relay}/socket`, {
      headers: { Upgrade: "websocket" },
    }),
  );
  const socket = response.webSocket;
  if (!socket) {
    throw new Error(
      `relay socket upgrade failed: ${response.status} ${await response.text()}`,
    );
  }
  socket.accept();
  const peer = new RelayPeer(socket);
  peers.add(peer);
  return peer;
}

export async function openHost(
  relay: string,
  token = HOST_TOKEN,
  clientToken: string | undefined = CLIENT_TOKEN,
) {
  const peer = await connect(relay);
  peer.send({
    type: "hello",
    role: "host",
    relayId: relay,
    token,
    ...(clientToken === undefined ? {} : { clientToken }),
  });
  const ack = await peer.next();
  return { peer, ack };
}

export async function openClient(relay: string, token = CLIENT_TOKEN) {
  const peer = await connect(relay);
  peer.send({ type: "hello", role: "client", relayId: relay, token });
  const ack = await peer.next();
  return { peer, ack };
}

export function roomStub(relay: string) {
  return env.RELAY_ROOMS.get(env.RELAY_ROOMS.idFromName(relay));
}

export async function relayConfig(relay: string) {
  return runInDurableObject(roomStub(relay), (_instance, state) =>
    state.storage.sql
      .exec<{ key: string; value: string }>(
        "SELECT key, value FROM relay_config ORDER BY key",
      )
      .toArray(),
  );
}

export async function activeRequestIds(relay: string, role: "host" | "client") {
  return runInDurableObject(roomStub(relay), (_instance, state) =>
    state
      .getWebSockets()
      .map((socket) => socket.deserializeAttachment())
      .filter(
        (attachment): attachment is { role?: string; activeRequestIds: string[] } =>
          typeof attachment === "object" &&
          attachment !== null &&
          (attachment as { role?: string }).role === role,
      )
      .map((attachment) => attachment.activeRequestIds),
  );
}

export async function closeAllPeers() {
  // Workerd's client-side close event isn't guaranteed for locally closed
  // WebSocketPairs in the shared-storage test runtime. Keep cleanup bounded:
  // close owned peers; don't claim the DO close handler has fully drained.
  const closing = [...peers];
  peers.clear();
  for (const peer of closing) peer.close(1000, "test cleanup");
}
