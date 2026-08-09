declare module "cloudflare:workers" {
  export class DurableObject<Env = unknown> {
    protected readonly ctx: DurableObjectState;
    protected readonly env: Env;
    constructor(ctx: DurableObjectState, env: Env);
  }
}

type DurableObjectSqlCursor<T> = {
  toArray(): T[];
};

type DurableObjectSqlStorage = {
  exec<T = Record<string, unknown>>(
    query: string,
    ...bindings: unknown[]
  ): DurableObjectSqlCursor<T>;
};

type DurableObjectStorage = {
  readonly sql: DurableObjectSqlStorage;
};

interface DurableObjectState {
  readonly storage: DurableObjectStorage;
  acceptWebSocket(socket: WebSocket): void;
  getWebSockets(): WebSocket[];
}

interface WebSocket {
  serializeAttachment(value: unknown): void;
  deserializeAttachment(): unknown;
}

declare class WebSocketPair {
  0: WebSocket;
  1: WebSocket;
}

interface ResponseInit {
  webSocket?: WebSocket;
}

type DurableObjectId = object;

type DurableObjectStub = {
  fetch(request: Request): Promise<Response>;
};

interface DurableObjectNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): DurableObjectStub;
}
