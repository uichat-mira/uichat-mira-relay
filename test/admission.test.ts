import { describe, expect, it } from "vitest";
import { handleHello, type AdmissionPort } from "../src/room-admission.js";
import { readAttachment } from "../src/room-state.js";

const token = "h".repeat(48);
const clientToken = "c".repeat(48);
const roomId = "relay_1234567890abcdef";

function socket(id: string) {
  let attachment: unknown = {
    authenticated: false, connectionId: id, relayId: roomId, activeRequestIds: [],
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

function fixture() {
  const config = new Map<string, string>();
  const hosts: WebSocket[] = [];
  const failSocket = (sock: WebSocket, code: string) => {
    sock.send(JSON.stringify({ type: "error", code }));
    sock.close(1008);
  };
  const port: AdmissionPort = {
    readConfig: (key) => config.get(key) ?? null,
    writeConfig: (key, value) => { config.set(key, value); },
    hostSockets: () => hosts,
    failAllClientRequests: () => undefined,
    failSocket,
  };
  return { config, hosts, port };
}

describe("legacy Host/Client handshake remains unchanged after modularization", () => {
  it("requires legacy clientToken to initialize a room", async () => {
    const { port, config } = fixture();
    const host = socket("host1");
    await handleHello(port, host.sock, readAttachment(host.sock)!, {
      type: "hello", version: 1, role: "host", relayId: roomId, token,
    });
    expect(host.sent.at(-1)).toMatchObject({ code: "CLIENT_TOKEN_REQUIRED" });
    expect(host.closed).toEqual([1008]);
    expect(config.size).toBe(0);
  });

  it("stores hashes, never raw Host or Client tokens", async () => {
    const { port, config } = fixture();
    const host = socket("host1");
    await handleHello(port, host.sock, readAttachment(host.sock)!, {
      type: "hello", version: 1, role: "host", relayId: roomId, token, clientToken,
    });
    expect(host.closed).toEqual([]);
    expect(host.sent[0]).toMatchObject({
      type: "hello_ack", role: "host", relayId: roomId, protocolVersion: 1,
    });
    expect(readAttachment(host.sock)).toMatchObject({
      authenticated: true, role: "host",
    });
    expect(config.get("host_token_hash")).toMatch(/^[a-f0-9]{64}$/);
    expect(config.get("client_token_hash")).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify([...config.values()])).not.toContain(token);
  });

  it("rejects wrong Host token, wrong role and foreign room", async () => {
    const { port, config } = fixture();
    config.set("host_token_hash", "0".repeat(64));
    const bad = socket("bad");
    await handleHello(port, bad.sock, readAttachment(bad.sock)!, {
      type: "hello", version: 1, role: "host", relayId: roomId, token,
    });
    expect(bad.sent.at(-1)).toMatchObject({ code: "HOST_AUTH_FAILED" });
    const foreign = socket("foreign");
    await handleHello(port, foreign.sock, readAttachment(foreign.sock)!, {
      type: "hello", version: 1, role: "client", relayId: "wrong_room",
      token: clientToken,
    });
    expect(foreign.sent.at(-1)).toMatchObject({ code: "INVALID_HELLO" });
  });

  it("accepts the correct stored Client token and denies a different one", async () => {
    const { port } = fixture();
    const host = socket("host");
    await handleHello(port, host.sock, readAttachment(host.sock)!, {
      version: 1, type: "hello", role: "host", relayId: roomId, token, clientToken,
    });
    const client = socket("client");
    await handleHello(port, client.sock, readAttachment(client.sock)!, {
      version: 1, type: "hello", role: "client", relayId: roomId, token: clientToken,
    });
    expect(client.sent[0]).toMatchObject({ type: "hello_ack", role: "client" });
    expect(readAttachment(client.sock)?.authenticated).toBe(true);
    const bad = socket("client-bad");
    await handleHello(port, bad.sock, readAttachment(bad.sock)!, {
      version: 1, type: "hello", role: "client",
      relayId: roomId, token: "z".repeat(48),
    });
    expect(bad.sent.at(-1)).toMatchObject({ code: "CLIENT_AUTH_FAILED" });
  });
});
