import { describe, expect, it } from "vitest";
import {
  PROTOCOL_VERSION,
  internalRequestId,
  normalizeToken,
  parseFrame,
  parseInternalRequestId,
  parseRelayId,
  requestIdFrom,
} from "../src/protocol.js";

const room = "relay_1234567890abcdef";

describe("Relay V1 frame/room contract", () => {
  it("accepts one bounded room path, not aliases or malformed paths", () => {
    expect(parseRelayId(`/v1/relay/${room}/socket`)).toBe(room);
    expect(parseRelayId("/v1/relay/short/socket")).toBeNull();
    expect(parseRelayId(`/v1/relay/${room}/socket/extra`)).toBeNull();
    expect(parseRelayId(`/v1/relay/${"a".repeat(129)}/socket`)).toBeNull();
  });

  it("rejects invalid version, missing type, malformed JSON and oversized frames", () => {
    expect(parseFrame(JSON.stringify({ version: PROTOCOL_VERSION, type: "hello" })))
      .toMatchObject({ type: "hello" });
    expect(parseFrame(JSON.stringify({ version: 2, type: "hello" }))).toBeNull();
    expect(parseFrame('{"version":1}')).toBeNull();
    expect(parseFrame("{")).toBeNull();
    expect(parseFrame("x".repeat(2 * 1024 * 1024 + 1))).toBeNull();
  });

  it("keeps legacy token normalization within its original bounds", () => {
    expect(normalizeToken(" x ".trim().repeat(32))).toBe("x".repeat(32));
    expect(normalizeToken("a".repeat(31))).toBeNull();
    expect(normalizeToken("a".repeat(513))).toBeNull();
    expect(normalizeToken(123)).toBeNull();
  });

  it("routes request IDs to the originating connection and validates input", () => {
    const frame = { version: 1, type: "request", requestId: "req_1" };
    expect(requestIdFrom(frame)).toBe("req_1");
    const routed = internalRequestId("conn-1", "req_1");
    expect(parseInternalRequestId(routed))
      .toEqual({ connectionId: "conn-1", requestId: "req_1" });
    expect(parseInternalRequestId("without-separator")).toBeNull();
    expect(parseInternalRequestId("conn~bad/id")).toBeNull();
    expect(requestIdFrom({ ...frame, requestId: "/bad" })).toBeNull();
  });
});
