import { describe, expect, it } from "vitest";
import { durableRoomKey, resolveAdmissionMode } from "../src/admission-mode.js";

describe("Relay deployment admission mode", () => {
  it("preserves the current Legacy default without Cloud configuration", () => {
    expect(resolveAdmissionMode({})).toBe("legacy");
    expect(resolveAdmissionMode({ RELAY_ADMISSION_MODE: "legacy" })).toBe("legacy");
  });

  it("requires an explicit, trusted HTTPS Cloud JWKS path", () => {
    const jwks = "https://cloud-auth.example/.well-known/jwks.json";
    expect(resolveAdmissionMode({ RELAY_ADMISSION_MODE: "cloud", CLOUD_AUTH_JWKS_URL: jwks }))
      .toBe("cloud");
    for (const config of [
      { CLOUD_AUTH_JWKS_URL: jwks },
      { RELAY_ADMISSION_MODE: "cloud" },
      { RELAY_ADMISSION_MODE: "legacy", CLOUD_AUTH_JWKS_URL: jwks },
      { RELAY_ADMISSION_MODE: "ClOuD", CLOUD_AUTH_JWKS_URL: jwks },
      { RELAY_ADMISSION_MODE: "cloud", CLOUD_AUTH_JWKS_URL: "http://cloud-auth.example/.well-known/jwks.json" },
      { RELAY_ADMISSION_MODE: "cloud", CLOUD_AUTH_JWKS_URL: "https://cloud-auth.example/unsafe" },
      { RELAY_ADMISSION_MODE: "cloud", CLOUD_AUTH_JWKS_URL: jwks + "?kid=x" },
    ]) {
      expect(resolveAdmissionMode(config)).toBeNull();
    }
  });

  it("keeps Cloud and Legacy room sockets/SQL storage in distinct DO keys", () => {
    const room = "relay_1234567890abcd";
    expect(durableRoomKey(room, "legacy")).toBe(room);
    expect(durableRoomKey(room, "cloud")).toBe(`cloud:${room}`);
  });
});
