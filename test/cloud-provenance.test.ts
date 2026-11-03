import { describe, expect, it } from "vitest";
import {
  handleClientFrame, handleCloudClientFrame, type ForwardPort,
} from "../src/room-forwarding.js";
import type { CloudClientIdentity } from "../src/room-state.js";
import { readAttachment } from "../src/room-state.js";

const relayId = "relay_1234567890abcdef";

function socket(
  id: string,
  role: "host" | "client",
  cloudClientIdentity?: CloudClientIdentity,
) {
  let attachment: unknown = {
    authenticated: true,
    connectionId: id,
    relayId,
    role,
    activeRequestIds: [],
    ...(cloudClientIdentity ? { cloudClientIdentity } : {}),
  };
  const sent: Array<Record<string, unknown>> = [];
  const closed: Array<{ code: number; message?: string }> = [];
  const sock = {
    deserializeAttachment: () => attachment,
    serializeAttachment: (value: unknown) => { attachment = value; },
    send: (frame: string) => sent.push(JSON.parse(frame)),
    close: (code: number, message?: string) => { closed.push({ code, message }); },
  } as unknown as WebSocket;
  return { sock, sent, closed };
}

const identity = (
  accountId: string,
  deviceId: string,
): CloudClientIdentity => ({ accountId, deviceId, room: relayId, role: "client" });

function port(host: ReturnType<typeof socket>, clients: Array<ReturnType<typeof socket>>) {
  const failed: Array<{ socket: WebSocket; code: string }> = [];
  const value: ForwardPort = {
    hostSockets: () => [host.sock],
    clientSockets: () => clients.map((client) => client.sock),
    failSocket: (socket, code) => {
      failed.push({ socket, code });
      socket.close(1008);
    },
  };
  return { value, failed };
}

describe("Cloud Client provenance forwarding contract", () => {
  it("authors provenance, strips top-level forgeries, and preserves nested business data", () => {
    const host = socket("host-1", "host");
    const client = socket("client-1", "client", identity("account-a", "mobile-a"));
    const forwarding = port(host, [client]);

    handleCloudClientFrame(
      forwarding.value,
      client.sock,
      readAttachment(client.sock)!,
      {
        version: 1,
        type: "request",
        requestId: "req-1",
        method: "GET",
        path: "/remote/v1/manifest",
        relayProvenance: {
          version: 1,
          transport: "cloud",
          accountId: "account-b",
          deviceId: "foreign-mobile",
        },
        identity: { accountId: "account-b", deviceId: "foreign-mobile" },
        mobileDeviceId: "foreign-mobile",
        deviceId: "foreign-mobile",
        accountId: "account-b",
        payload: {
          identity: { deviceId: "foreign-mobile" },
          caller: "foreign-mobile",
          keep: "business-value",
        },
      },
    );

    expect(host.sent).toHaveLength(1);
    expect(host.sent[0]).toMatchObject({
      type: "request",
      requestId: "client-1~req-1",
      method: "GET",
      path: "/remote/v1/manifest",
      relayProvenance: {
        version: 1,
        transport: "cloud",
        accountId: "account-a",
        deviceId: "mobile-a",
        room: relayId,
        role: "client",
        connectionId: "client-1",
        requestId: "client-1~req-1",
      },
      payload: { identity: { deviceId: "foreign-mobile" }, caller: "foreign-mobile", keep: "business-value" },
    });
    expect(host.sent[0]).not.toHaveProperty("identity");
    expect(host.sent[0]).not.toHaveProperty("mobileDeviceId");
    expect(host.sent[0]).not.toHaveProperty("deviceId");
    expect(host.sent[0]).not.toHaveProperty("accountId");
    expect(host.sent[0]).toHaveProperty("payload.identity.deviceId", "foreign-mobile");
    expect(host.sent[0]).toHaveProperty("payload.caller", "foreign-mobile");
  });

  it("fails closed when verified Cloud identity is missing, malformed or for another room", () => {
    const host = socket("host-1", "host");
    const cases = [
      socket("client-none", "client"),
      socket("client-wrong-room", "client", {
        accountId: "account-a",
        deviceId: "mobile-a",
        room: "relay_other_room_000",
        role: "client",
      }),
      socket("client-empty", "client", {
        accountId: "",
        deviceId: "mobile-a",
        room: relayId,
        role: "client",
      }),
    ];

    for (const client of cases) {
      const forwarding = port(host, [client]);
      handleCloudClientFrame(
        forwarding.value,
        client.sock,
        readAttachment(client.sock)!,
        { version: 1, type: "request", requestId: "req-1" },
      );
      expect(forwarding.failed).toEqual([{
        socket: client.sock,
        code: "CLOUD_CLIENT_IDENTITY_UNAVAILABLE",
      }]);
      expect(client.closed[0]?.code).toBe(1008);
    }
    expect(host.sent).toEqual([]);
  });

  it("keeps per-socket provenance distinct for multiple Mobile clients", () => {
    const host = socket("host-1", "host");
    const first = socket("client-a", "client", identity("account-a", "mobile-a"));
    const second = socket("client-b", "client", identity("account-a", "mobile-b"));
    const forwarding = port(host, [first, second]);

    for (const client of [first, second]) {
      handleCloudClientFrame(
        forwarding.value,
        client.sock,
        readAttachment(client.sock)!,
        { version: 1, type: "request", requestId: "same-id" },
      );
    }

    expect(host.sent.map((frame) => frame.relayProvenance)).toEqual([
      expect.objectContaining({
        deviceId: "mobile-a",
        connectionId: "client-a",
        requestId: "client-a~same-id",
      }),
      expect.objectContaining({
        deviceId: "mobile-b",
        connectionId: "client-b",
        requestId: "client-b~same-id",
      }),
    ]);
  });

  it("carries the same server-authored provenance on cancellation", () => {
    const host = socket("host-1", "host");
    const client = socket("client-1", "client", identity("account-a", "mobile-a"));
    const forwarding = port(host, [client]);

    handleCloudClientFrame(
      forwarding.value,
      client.sock,
      readAttachment(client.sock)!,
      {
        version: 1,
        type: "request",
        requestId: "req-1",
        relayProvenance: { deviceId: "forged" },
      },
    );
    handleCloudClientFrame(
      forwarding.value,
      client.sock,
      readAttachment(client.sock)!,
      {
        version: 1,
        type: "cancel",
        requestId: "req-1",
        relayProvenance: { deviceId: "forged" },
      },
    );

    expect(host.sent.map((frame) => frame.relayProvenance)).toEqual([
      expect.objectContaining({ deviceId: "mobile-a", requestId: "client-1~req-1" }),
      expect.objectContaining({ deviceId: "mobile-a", requestId: "client-1~req-1" }),
    ]);
  });

  it("leaves Legacy forwarding free of Cloud provenance and unchanged", () => {
    const host = socket("host-1", "host");
    const client = socket("client-1", "client");
    const forwarding = port(host, [client]);

    handleClientFrame(
      forwarding.value,
      client.sock,
      readAttachment(client.sock)!,
      {
        version: 1,
        type: "request",
        requestId: "req-1",
        method: "GET",
        identity: { deviceId: "caller-supplied" },
      },
    );

    expect(host.sent).toEqual([{
      version: 1,
      type: "request",
      requestId: "client-1~req-1",
      method: "GET",
      identity: { deviceId: "caller-supplied" },
    }]);
  });
});
