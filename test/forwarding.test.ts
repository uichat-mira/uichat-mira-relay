import { describe, expect, it } from "vitest";
import {
  handleClientFrame, handleHostFrame, type ForwardPort,
} from "../src/room-forwarding.js";
import { readAttachment } from "../src/room-state.js";

function socket(id: string, role: "host" | "client") {
  let attachment: unknown = {
    authenticated: true, connectionId: id,
    relayId: "relay_1234567890abcdef", role, activeRequestIds: [],
  };
  const sent: Array<Record<string, unknown>> = [];
  const closed: number[] = [];
  const sock = {
    deserializeAttachment: () => attachment,
    serializeAttachment: (value: unknown) => { attachment = value; },
    send: (frame: string) => sent.push(JSON.parse(frame)),
    close: (code: number) => { closed.push(code); },
  } as unknown as WebSocket;
  return { sock, sent, closed };
}

describe("legacy routed request/response semantics", () => {
  it("routes a client request, completes it and clears the active set", () => {
    const host = socket("host-1", "host");
    const client = socket("client-1", "client");
    const port: ForwardPort = {
      hostSockets: () => [host.sock],
      clientSockets: () => [client.sock],
      failSocket: (s) => { s.close(1008); },
    };
    handleClientFrame(port, client.sock, readAttachment(client.sock)!, {
      type: "request", version: 1, requestId: "req_1",
      method: "GET", path: "/remote/v1/manifest",
    });
    expect(host.sent[0]).toMatchObject({
      type: "request", requestId: "client-1~req_1",
    });
    expect(readAttachment(client.sock)?.activeRequestIds).toEqual(["req_1"]);
    handleHostFrame(port, host.sock, {
      type: "complete", version: 1, requestId: "client-1~req_1",
    });
    expect(client.sent[0]).toMatchObject({ type: "complete", requestId: "req_1" });
    expect(readAttachment(client.sock)?.activeRequestIds).toEqual([]);
  });

  it("cancels active requests with the correct connection-qualified id", () => {
    const host = socket("host-1", "host");
    const client = socket("client-1", "client");
    const port: ForwardPort = {
      hostSockets: () => [host.sock], clientSockets: () => [client.sock],
      failSocket: () => undefined,
    };
    const req = { version: 1, requestId: "r1" };
    handleClientFrame(port, client.sock, readAttachment(client.sock)!, {
      ...req, type: "request",
    });
    handleClientFrame(port, client.sock, readAttachment(client.sock)!, {
      ...req, type: "cancel",
    });
    expect(host.sent.at(-1)).toMatchObject({
      type: "cancel", requestId: "client-1~r1",
    });
    expect(readAttachment(client.sock)?.activeRequestIds).toEqual([]);
  });

  it("rejects a stale or foreign response instead of forwarding data", () => {
    const host = socket("host-1", "host");
    const client = socket("client-1", "client");
    const port: ForwardPort = {
      hostSockets: () => [host.sock], clientSockets: () => [client.sock],
      failSocket: () => undefined,
    };
    handleHostFrame(port, host.sock, {
      version: 1, type: "chunk", requestId: "unknown~req_1", data: "secret",
    });
    expect(client.sent).toEqual([]);
    expect(host.sent.at(-1)).toMatchObject({ type: "cancel" });
  });
});
