import { beforeAll, describe, expect, it } from "vitest";
import {
  ProbeError,
  errorCode,
  failureCategory,
  importJwks,
  parseProbeConfig,
  redactDiagnostic,
  verifyShiyanClaims,
  verifyTicket,
} from "../scripts/cloud-probe-contract.mjs";
import {
  KEY_ID,
  NEXT_KEY_ID,
  ROOM,
  createSigningFixture,
  jwks,
  relayClaims,
  signTicket,
  ticketHeader,
} from "./cloud-relay-fixtures.js";

type SigningFixture = Awaited<ReturnType<typeof createSigningFixture>>;
let primary: SigningFixture;
let other: SigningFixture;

const VALID_ENV = {
  REL005_AUTH_ORIGIN: "https://auth.example.com",
  REL005_RELAY_ORIGIN: "wss://relay-staging.example.workers.dev",
  REL005_ROOM: "room_0123456789abcdef",
  REL005_HOST_SESSION: "host-session",
  REL005_CLIENT_SESSION: "client-session",
  REL005_FOREIGN_SESSION: "foreign-session",
};

beforeAll(async () => {
  primary = await createSigningFixture(KEY_ID);
  other = await createSigningFixture(NEXT_KEY_ID);
});

const currentClaims = (overrides: Record<string, unknown> = {}) => {
  const now = Math.floor(Date.now() / 1000);
  return relayClaims({ iat: now, nbf: now, exp: now + 300, ...overrides });
};

const trustedKeys = async (
  entries: ReadonlyArray<{ kid: string; jwk: Record<string, unknown> }> = [
    { kid: KEY_ID, jwk: primary.publicJwk },
  ],
) => importJwks(jwks(entries));

const expectProbeError = async (
  action: () => Promise<unknown> | unknown,
  stage: string,
  message: RegExp,
) => {
  try {
    await action();
  } catch (error) {
    expect(error).toBeInstanceOf(ProbeError);
    expect(failureCategory(error)).toBe(stage);
    expect((error as Error).message).toMatch(message);
    return error as Error;
  }
  throw new Error(`Expected ProbeError ${stage}`);
};

describe("REL-005 live probe fail-closed configuration", () => {
  it("accepts only distinct bare trusted origins and a Relay room id", () => {
    expect(parseProbeConfig(VALID_ENV)).toEqual({
      auth: "https://auth.example.com",
      relay: "wss://relay-staging.example.workers.dev",
      room: VALID_ENV.REL005_ROOM,
      sessions: {
        host: "host-session",
        client: "client-session",
        foreign: "foreign-session",
      },
    });
  });

  it("rejects production, insecure, non-bare and missing inputs without echoing values", async () => {
    const cases: Array<[Record<string, string>, RegExp]> = [
      [{ ...VALID_ENV, REL005_RELAY_ORIGIN: "wss://relay.tomz.io" }, /Legacy production/u],
      [{ ...VALID_ENV, REL005_AUTH_ORIGIN: "http://auth.example.com" }, /bare https:/u],
      [{ ...VALID_ENV, REL005_AUTH_ORIGIN: "https://auth.example.com/api" }, /bare https:/u],
      [{ ...VALID_ENV, REL005_RELAY_ORIGIN: "wss://relay.example.com/?token=x" }, /bare wss:/u],
      [{ ...VALID_ENV, REL005_ROOM: "short" }, /ROOM is invalid/u],
      [{ ...VALID_ENV, REL005_HOST_SESSION: "" }, /HOST_SESSION is required/u],
      [
        { ...VALID_ENV, REL005_CLIENT_SESSION: VALID_ENV.REL005_HOST_SESSION },
        /must be distinct/u,
      ],
    ];

    for (const [env, message] of cases) {
      const error = await expectProbeError(
        () => parseProbeConfig(env),
        "CONFIG",
        message,
      );
      if (env.REL005_HOST_SESSION) {
        expect(redactDiagnostic(error)).not.toContain(env.REL005_HOST_SESSION);
      }
      expect(redactDiagnostic(error)).not.toContain(env.REL005_ROOM);
    }
  });

  it("classifies failures without exposing credentials, JWT material or room paths", () => {
    const token = "header00.payload0.signature";
    const opaqueToken = "c".repeat(48);
    const diagnostics = [
      redactDiagnostic(new Error(`failed with Bearer ${token}`)),
      redactDiagnostic(new Error(`failed with ${token}`)),
      redactDiagnostic(new Error(`failed with ${opaqueToken}`)),
      redactDiagnostic(new Error("failed at /v1/relay/room_0123456789abcdef/socket")),
      redactDiagnostic("plain\nfailure"),
    ];
    for (const diagnostic of diagnostics) {
      expect(diagnostic).not.toContain(token);
      expect(diagnostic).not.toContain(opaqueToken);
      expect(diagnostic).not.toContain("room_0123456789abcdef");
      expect(diagnostic).not.toContain("\n");
      expect(diagnostic.length).toBeLessThanOrEqual(300);
    }
    expect(failureCategory(new Error("not staged"))).toBe("UNKNOWN");
  });

  it("accepts only a bounded server error code", () => {
    expect(errorCode({
      error: { code: "SERVICE_CREDENTIAL_RELAY_NOT_AUTHORIZED" },
    })).toBe("SERVICE_CREDENTIAL_RELAY_NOT_AUTHORIZED");
    for (const payload of [
      { error: { code: "<html>portal</html>" } },
      { error: { code: "A".repeat(81) } },
      { error: "not-an-object" },
      null,
    ]) {
      expect(errorCode(payload)).toBe("INVALID_ERROR");
    }
  });
});

describe("REL-005 live probe local ticket verification", () => {
  it("verifies a current Relay ticket against the HTTPS JWKS material", async () => {
    const ticket = await signTicket(primary.privateKey, currentClaims({
      relay: { room: ROOM, role: "host" },
    }));
    const claims = await verifyTicket(ticket, await trustedKeys(), {
      room: ROOM, role: "host",
    });
    expect(claims.relay).toEqual({ room: ROOM, role: "host" });
    expect(claims.aud).toBe("mira:cloud-relay-transport");
  });

  it("denies wrong room, role, audience, expiry, key and Legacy tokens before admission", async () => {
    const keys = await trustedKeys();
    const cases: Array<[string, unknown, RegExp]> = [
      [
        await signTicket(primary.privateKey, currentClaims({
          relay: { room: ROOM, role: "client" },
        })),
        { room: "room_ffffffffffffffff", role: "client" },
        /room mismatch/u,
      ],
      [
        await signTicket(primary.privateKey, currentClaims({
          relay: { room: ROOM, role: "client" },
        })),
        { room: ROOM, role: "host" },
        /role mismatch/u,
      ],
      [
        await signTicket(primary.privateKey, currentClaims({ aud: "mira:cloud-shiyan" })),
        { room: ROOM, role: "client" },
        /audience mismatch/u,
      ],
      [
        await signTicket(primary.privateKey, currentClaims({
          iat: Math.floor(Date.now() / 1000) - 600,
          nbf: Math.floor(Date.now() / 1000) - 600,
          exp: Math.floor(Date.now() / 1000) - 1,
        })),
        { room: ROOM, role: "client" },
        /expired/u,
      ],
      [
        await signTicket(other.privateKey, currentClaims(),
          ticketHeader({ kid: KEY_ID })),
        { room: ROOM, role: "client" },
        /signature is invalid/u,
      ],
      [
        await signTicket(primary.privateKey, currentClaims(),
          ticketHeader({ kid: "untrusted-key" })),
        { room: ROOM, role: "client" },
        /absent from trusted JWKS/u,
      ],
      ["c".repeat(48), { room: ROOM, role: "client" }, /compact JWS/u],
    ];

    for (const [token, expected, message] of cases) {
      const error = await expectProbeError(
        () => verifyTicket(token, keys, expected),
        "TICKET",
        message,
      );
      expect(redactDiagnostic(error)).not.toContain(token);
    }
  });

  it("separates the Shiyan audience from Relay transport tickets", async () => {
    const keys = await trustedKeys();
    const shiyan = await signTicket(primary.privateKey, currentClaims({
      aud: "mira:cloud-shiyan",
    }));
    expect((await verifyShiyanClaims(shiyan, keys)).aud).toBe("mira:cloud-shiyan");
    const relayTicket = await signTicket(primary.privateKey, currentClaims());
    await expectProbeError(
      () => verifyShiyanClaims(relayTicket, keys),
      "TICKET",
      /audience mismatch/u,
    );
  });

  it("rejects Portal HTML, duplicate kids and non-Ed25519 keys as untrusted JWKS", async () => {
    const cases: unknown[] = [
      "<html>portal</html>",
      { keys: [] },
      { keys: [{ ...primary.publicJwk, kid: KEY_ID }],
        extra: true },
      { keys: [
        { ...primary.publicJwk, kid: KEY_ID },
        { ...other.publicJwk, kid: KEY_ID },
      ] },
      { keys: [{ ...primary.publicJwk, alg: "RS256" }] },
    ];
    for (const payload of cases) {
      await expectProbeError(
        () => importJwks(payload),
        "JWKS",
        /JWKS|public key/u,
      );
    }
  });
});
