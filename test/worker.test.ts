import { describe, expect, it } from "vitest";
import { exports } from "cloudflare:workers";

describe("Relay Worker routing in workerd", () => {
  it("serves a minimal health response without persisted data", async () => {
    const res = await exports.default.fetch("https://relay.test/health");
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toEqual({
      ok: true, service: "mira-remote-relay", protocolVersion: 1,
    });
  });

  it("rejects malformed room paths before touching Durable Objects", async () => {
    const res = await exports.default.fetch("https://relay.test/v1/relay/bad/socket");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "not_found" });
  });

  it("requires a WebSocket upgrade for a valid room route", async () => {
    const res = await exports.default.fetch(
      "https://relay.test/v1/relay/relay_1234567890abcdef/socket",
    );
    expect(res.status).toBe(426);
    expect(await res.json()).toEqual({ error: "websocket_required" });
  });
});
