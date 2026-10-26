import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { CompactSign, importJWK } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import { closeAllPeers, connect, roomId, type RelayPeer } from "./room-harness.js";

afterEach(closeAllPeers);

const keyPromise = importJWK(
  JSON.parse((env as unknown as { TEST_SIGNING_PRIVATE_JWK: string }).TEST_SIGNING_PRIVATE_JWK),
  "EdDSA",
);
const encoder = new TextEncoder();

async function ticket(
  room: string,
  role: "host" | "client",
  overrides: Record<string, unknown> = {},
) {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: "mira:cloud-auth",
    sub: "account-a",
    device_id: role === "host" ? "desktop-a" : "mobile-a",
    aud: "mira:cloud-relay-transport",
    scope: ["relay:transport"],
    relay: { room, role },
    iat: now - 1,
    nbf: now - 1,
    exp: now + 300,
    ...overrides,
  };
  return new CompactSign(encoder.encode(JSON.stringify(claims)))
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT", kid: "rel004-test-key" })
    .sign(await keyPromise);
}

async function join(room: string, role: "host" | "client", token: string, extras = {}) {
  const peer = await connect(room);
  peer.send({ type: "hello", role, relayId: room, token, ...extras });
  return peer;
}

async function denied(peer: RelayPeer, code: string) {
  const response = await peer.next();
  expect(response).toMatchObject({ type: "error", code });
  expect((await peer.expectClose()).code).toBe(1008);
  expect(peer.received.some((frame) => frame.type === "hello_ack")).toBe(false);
}

describe("Cloud-only Host/Client admission through real DO WebSockets", () => {
  it("admits signed Host and Client without provisioning Legacy SQL and forwards V1 frames", async () => {
    const room = roomId("cloud-forward");
    const host = await join(room, "host", await ticket(room, "host"));
    expect(await host.next()).toMatchObject({
      type: "hello_ack", role: "host", relayId: room, protocolVersion: 1,
    });
    const client = await join(room, "client", await ticket(room, "client"));
    expect(await client.next()).toMatchObject({
      type: "hello_ack", role: "client", hostConnected: true,
    });
    client.send({ type: "request", requestId: "cloud-req", path: "/remote/v1/manifest" });
    const forwarded = await host.next();
    expect(forwarded.type).toBe("request");
    expect(forwarded.requestId).toMatch(/~cloud-req$/);
    host.send({ type: "complete", requestId: forwarded.requestId });
    expect(await client.next()).toMatchObject({ type: "complete", requestId: "cloud-req" });

    // Cloud uses its own DO key, and does not create legacy token hashes.
    const cloudRoom = env.RELAY_ROOMS.get(env.RELAY_ROOMS.idFromName(`cloud:${room}`));
    const stored = await runInDurableObject(cloudRoom, (_instance, state) =>
      state.storage.sql.exec("SELECT key FROM relay_config").toArray(),
    );
    expect(stored).toEqual([]);
  });

  it("fails closed for wrong room, role, signature, audience, expiry and Legacy tokens", async () => {
    const room = roomId("cloud-denied");
    const other = roomId("cloud-other");
    const bad = [
      [await ticket(other, "client"), "CLOUD_TICKET_REJECTED"],
      [await ticket(room, "host"), "CLOUD_TICKET_REJECTED"],
      [await ticket(room, "client", { aud: "mira:cloud-shiyan" }), "CLOUD_TICKET_REJECTED"],
      [await ticket(room, "client", { exp: Math.floor(Date.now() / 1000) - 1 }), "CLOUD_TICKET_REJECTED"],
      ["c".repeat(48), "CLOUD_TICKET_REJECTED"],
    ] as const;
    for (const [token, code] of bad) {
      await denied(await join(room, "client", token), code);
    }
    const foreign = await ticket(room, "client");
    const parts = foreign.split(".");
    parts[1] = parts[1]!.slice(0, -2) + "AB";
    await denied(await join(room, "client", parts.join(".")), "CLOUD_TICKET_REJECTED");

    await denied(await join(room, "host", await ticket(room, "host"), {
      clientToken: "a".repeat(48),
    }), "CLOUD_LEGACY_PROVISION_FORBIDDEN");

    const missing = await connect(room);
    missing.send({ type: "hello", role: "client", relayId: room });
    await denied(missing, "CLOUD_TICKET_REQUIRED");
  });

  it("keeps an admitted connection alive after ticket expiry but revalidates reconnect", async () => {
    const room = roomId("cloud-expire");
    const host = await join(room, "host", await ticket(room, "host"));
    await host.next();
    const now = Math.floor(Date.now() / 1000);
    const short = await ticket(room, "client", { iat: now - 1, nbf: now - 1, exp: now + 1 });
    const client = await join(room, "client", short);
    expect(await client.next()).toMatchObject({ type: "hello_ack" });

    await new Promise((resolve) => setTimeout(resolve, 1_400));
    client.send({ type: "request", requestId: "after-exp" });
    const forwarded = await host.next();
    expect(forwarded.requestId).toMatch(/~after-exp$/);
    host.send({ type: "complete", requestId: forwarded.requestId });
    expect(await client.next()).toMatchObject({ type: "complete", requestId: "after-exp" });

    await denied(await join(room, "client", short), "CLOUD_TICKET_REJECTED");
  });

  it("never authenticates a second request while first Cloud hello is pending", async () => {
    const room = roomId("cloud-pending");
    const peer = await connect(room);
    peer.send({ type: "hello", role: "client", relayId: room, token: await ticket(room, "client") });
    peer.send({ type: "request", requestId: "too-early" });
    const first = await peer.next();
    expect(["CLOUD_HELLO_PENDING", "HELLO_REQUIRED"]).toContain(first.code);
    expect((await peer.expectClose()).code).toBe(1008);
    expect(peer.received.some((frame) => frame.type === "hello_ack")).toBe(false);
  });
});
