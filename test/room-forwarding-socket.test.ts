import { afterEach, describe, expect, it } from "vitest";
import {
  CLIENT_TOKEN,
  HOST_TOKEN,
  activeRequestIds,
  closeAllPeers,
  openClient,
  openHost,
  relayConfig,
  roomId,
} from "./room-harness.js";

const routedPart = (frame: Record<string, unknown>) => {
  const routed = String(frame.requestId).split("~");
  expect(routed).toHaveLength(2);
  return { connectionId: routed[0], requestId: routed[1] };
};

afterEach(closeAllPeers);

describe("Legacy Relay V1 forwarding over real Durable Object WebSockets", () => {
  it("routes request, response and complete with client requestId ownership", async () => {
    const relay = roomId("roundtrip");
    const host = await openHost(relay);
    const client = await openClient(relay);

    client.peer.send({
      type: "request",
      requestId: "req_roundtrip",
      method: "POST",
      path: "/remote/v1/session",
      body: "private request body",
    });
    const forwarded = await host.peer.next();
    expect(forwarded).toMatchObject({
      type: "request",
      method: "POST",
      path: "/remote/v1/session",
    });
    const routed = routedPart(forwarded);
    expect(routed.requestId).toBe("req_roundtrip");
    expect(routed.connectionId).not.toBe("req_roundtrip");
    expect(await activeRequestIds(relay, "client")).toEqual([["req_roundtrip"]]);

    host.peer.send({
      type: "response",
      requestId: forwarded.requestId,
      status: 200,
      body: "private response body",
    });
    expect(await client.peer.next()).toMatchObject({
      type: "response",
      requestId: "req_roundtrip",
      status: 200,
      body: "private response body",
    });

    host.peer.send({ type: "complete", requestId: forwarded.requestId });
    expect(await client.peer.next()).toMatchObject({
      type: "complete",
      requestId: "req_roundtrip",
    });
    expect(await activeRequestIds(relay, "client")).toEqual([[]]);

    const persisted = JSON.stringify(await relayConfig(relay));
    expect(persisted).not.toContain(HOST_TOKEN);
    expect(persisted).not.toContain(CLIENT_TOKEN);
    expect(persisted).not.toContain("private request body");
    expect(persisted).not.toContain("private response body");
  });

  it("forwards cancel only for an active request and clears it", async () => {
    const relay = roomId("cancel");
    const host = await openHost(relay);
    const client = await openClient(relay);

    client.peer.send({ type: "request", requestId: "req_cancel" });
    const forwarded = await host.peer.next();
    routedPart(forwarded);
    expect(await activeRequestIds(relay, "client")).toEqual([["req_cancel"]]);

    client.peer.send({ type: "cancel", requestId: "req_cancel" });
    const cancelled = await host.peer.next();
    expect(cancelled).toMatchObject({
      type: "cancel",
      requestId: forwarded.requestId,
    });
    expect(await activeRequestIds(relay, "client")).toEqual([[]]);

    client.peer.send({ type: "cancel", requestId: "req_not_active" });
    // Same-client ordering barrier: the Host must receive the next request
    // before silence can prove the preceding invalid cancel was not forwarded.
    client.peer.send({ type: "request", requestId: "req_barrier" });
    const barrier = await host.peer.next();
    expect(barrier.type).toBe("request");
    expect(routedPart(barrier).requestId).toBe("req_barrier");
    await host.peer.expectSilence();
    host.peer.send({ type: "complete", requestId: barrier.requestId });
    expect(await client.peer.next()).toMatchObject({
      type: "complete",
      requestId: "req_barrier",
    });
  });

  it("does not cross-route foreign or stale host responses to another client", async () => {
    const relay = roomId("isolation");
    const host = await openHost(relay);
    const clientA = await openClient(relay);
    const clientB = await openClient(relay);

    clientA.peer.send({ type: "request", requestId: "req_a" });
    const requestA = await host.peer.next();
    clientB.peer.send({ type: "request", requestId: "req_b" });
    const requestB = await host.peer.next();
    routedPart(requestA);
    routedPart(requestB);

    host.peer.send({
      type: "response",
      requestId: requestA.requestId,
      body: "only for A",
    });
    expect(await clientA.peer.next()).toMatchObject({
      type: "response",
      requestId: "req_a",
      body: "only for A",
    });
    await clientB.peer.expectSilence();

    host.peer.send({ type: "complete", requestId: requestA.requestId });
    expect(await clientA.peer.next()).toMatchObject({
      type: "complete",
      requestId: "req_a",
    });
    await clientB.peer.expectSilence();

    host.peer.send({ type: "chunk", requestId: requestA.requestId, data: "stale" });
    expect(await host.peer.next()).toMatchObject({
      type: "cancel",
      requestId: requestA.requestId,
    });
    await clientA.peer.expectSilence();
    await clientB.peer.expectSilence();

    host.peer.send({
      type: "chunk",
      requestId: "unknown~req_b",
      data: "foreign",
    });
    expect(await host.peer.next()).toMatchObject({ type: "cancel" });
    await clientA.peer.expectSilence();
    await clientB.peer.expectSilence();

    host.peer.send({ type: "complete", requestId: requestB.requestId });
    expect(await clientB.peer.next()).toMatchObject({
      type: "complete",
      requestId: "req_b",
    });
    await clientA.peer.expectSilence();
  });
});
