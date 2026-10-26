import { afterEach, describe, expect, it } from "vitest";
import {
  CLIENT_TOKEN,
  HOST_TOKEN,
  closeAllPeers,
  connect,
  openClient,
  openHost,
  relayConfig,
  roomId,
} from "./room-harness.js";

const sha256Hex = async (value: string) => {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
};

afterEach(closeAllPeers);

describe("Legacy Relay V1 handshake over real Durable Object WebSockets", () => {
  it("accepts Host and Client peers and persists only token hashes", async () => {
    const relay = roomId("handshake");

    const host = await openHost(relay);
    expect(host.ack).toMatchObject({
      type: "hello_ack",
      role: "host",
      relayId: relay,
      protocolVersion: 1,
    });

    const client = await openClient(relay);
    expect(client.ack).toMatchObject({
      type: "hello_ack",
      role: "client",
      relayId: relay,
      protocolVersion: 1,
      hostConnected: true,
    });

    const rows = await relayConfig(relay);
    expect(rows.map((row) => row.key)).toEqual([
      "client_token_hash",
      "host_token_hash",
    ]);
    expect(rows.find((row) => row.key === "host_token_hash")?.value)
      .toBe(await sha256Hex(HOST_TOKEN));
    expect(rows.find((row) => row.key === "client_token_hash")?.value)
      .toBe(await sha256Hex(CLIENT_TOKEN));
    expect(JSON.stringify(rows)).not.toContain(HOST_TOKEN);
    expect(JSON.stringify(rows)).not.toContain(CLIENT_TOKEN);
  });

  it("rejects a wrong token and does not let that peer forward", async () => {
    const relay = roomId("wrongtoken");
    const host = await openHost(relay);
    const client = await openClient(relay);

    const badHost = await connect(relay);
    badHost.send({
      type: "hello",
      role: "host",
      relayId: relay,
      token: "x".repeat(48),
    });
    expect(await badHost.next()).toMatchObject({ code: "HOST_AUTH_FAILED" });
    expect((await badHost.expectClose()).code).toBe(1008);

    const badClient = await connect(relay);
    badClient.send({
      type: "hello",
      role: "client",
      relayId: relay,
      token: "x".repeat(48),
    });
    expect(await badClient.next()).toMatchObject({ code: "CLIENT_AUTH_FAILED" });
    expect((await badClient.expectClose()).code).toBe(1008);

    try {
      badHost.send({ type: "response", requestId: "unknown~bad_req", body: "leak" });
    } catch {
      // The rejected socket is already closed.
    }
    try {
      badClient.send({
        type: "request",
        requestId: "bad_req",
        method: "GET",
        path: "/remote/v1/manifest",
      });
    } catch {
      // The rejected socket is already closed.
    }
    await client.peer.expectSilence();
    await host.peer.expectSilence();
  });

  it("rejects malformed and foreign-room frames before forwarding", async () => {
    const relay = roomId("malformed");
    const host = await openHost(relay);

    const malformed = await connect(relay);
    malformed.sendRaw("{");
    expect(await malformed.next()).toMatchObject({ code: "INVALID_FRAME" });
    expect((await malformed.expectClose()).code).toBe(1008);

    const foreign = await connect(relay);
    foreign.send({
      type: "hello",
      role: "client",
      relayId: roomId("foreign"),
      token: CLIENT_TOKEN,
    });
    expect(await foreign.next()).toMatchObject({ code: "INVALID_HELLO" });
    expect((await foreign.expectClose()).code).toBe(1008);

    await host.peer.expectSilence();
  });
});
