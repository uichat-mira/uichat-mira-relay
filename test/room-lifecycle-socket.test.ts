import { afterEach, describe, expect, it } from "vitest";
import {
  activeRequestIds,
  closeAllPeers,
  openClient,
  openHost,
  roomId,
} from "./room-harness.js";

afterEach(closeAllPeers);

describe("Legacy Relay V1 Host/Client lifecycle on real Durable Object WebSockets", () => {
  it("replaces the Host, clears active work and routes new requests to it", async () => {
    const relay = roomId("replace");
    const host1 = await openHost(relay);
    const client = await openClient(relay);

    client.peer.send({ type: "request", requestId: "req_old" });
    await host1.peer.next();
    expect(await activeRequestIds(relay, "client")).toEqual([["req_old"]]);

    const host2 = await openHost(relay);
    expect(host2.ack).toMatchObject({ type: "hello_ack", role: "host" });
    expect(await client.peer.next()).toMatchObject({
      type: "error",
      requestId: "req_old",
      code: "HOST_REPLACED",
      retryable: true,
    });
    expect((await host1.peer.expectClose()).code).toBe(1012);
    expect(await activeRequestIds(relay, "client")).toEqual([[]]);

    client.peer.send({ type: "request", requestId: "req_new" });
    const forwarded = await host2.peer.next();
    expect(forwarded).toMatchObject({ type: "request" });
    expect(String(forwarded.requestId).endsWith("~req_new")).toBe(true);
  });

  it("fails active work on Host disconnect and reports Host offline", async () => {
    const relay = roomId("hostdown");
    const host = await openHost(relay);
    const client = await openClient(relay);

    client.peer.send({ type: "request", requestId: "req_active" });
    await host.peer.next();
    host.peer.close(1000, "host going away");

    expect(await client.peer.next()).toMatchObject({
      type: "error",
      requestId: "req_active",
      code: "HOST_DISCONNECTED",
      retryable: true,
    });
    expect(await client.peer.next()).toMatchObject({
      type: "error",
      code: "HOST_DISCONNECTED",
      retryable: true,
    });
    expect(await activeRequestIds(relay, "client")).toEqual([[]]);

    client.peer.send({ type: "request", requestId: "req_offline" });
    expect(await client.peer.next()).toMatchObject({
      type: "error",
      requestId: "req_offline",
      code: "HOST_OFFLINE",
      retryable: true,
    });
  });

  it("cancels a disconnecting Client's active requests on the Host", async () => {
    const relay = roomId("clientleave");
    const host = await openHost(relay);
    const client = await openClient(relay);

    client.peer.send({ type: "request", requestId: "req_leave" });
    const forwarded = await host.peer.next();
    client.peer.close(1000, "client going away");

    expect(await host.peer.next()).toMatchObject({
      type: "cancel",
      requestId: forwarded.requestId,
    });
    expect(await activeRequestIds(relay, "client")).toEqual([]);
  });
});
