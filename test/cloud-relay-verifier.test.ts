import { beforeAll, describe, expect, it, vi } from "vitest";
import {
  createCloudRelayTicketVerifier,
  type CloudRelayTicketVerifierConfig,
} from "../src/cloud-relay-verifier.js";
import {
  CLOUD_RELAY_TICKET_MAX_LENGTH,
  CloudRelayTicketVerificationError,
  type CloudRelayTicketVerificationErrorCode,
} from "../src/cloud-relay-ticket.js";
import {
  ACCOUNT_ID,
  DEVICE_ID,
  FIXED_NOW,
  FIXED_NOW_SECONDS,
  KEY_ID,
  NEXT_KEY_ID,
  ROOM,
  MIRRORED_CLOUD_AUTH_CLAIMS_FIXTURE,
  createSigningFixture,
  encodeSegment,
  jwks,
  manualToken,
  relayClaims,
  roleContext,
  signTicket,
  ticketHeader,
} from "./cloud-relay-fixtures.js";

const JWKS_URL = "https://auth.example.com/.well-known/jwks.json";

type SigningFixture = Awaited<ReturnType<typeof createSigningFixture>>;
let primary: SigningFixture;
let other: SigningFixture;

beforeAll(async () => {
  primary = await createSigningFixture(KEY_ID);
  other = await createSigningFixture(NEXT_KEY_ID);
});

const expectVerificationError = async (
  action: () => Promise<unknown>,
  code: CloudRelayTicketVerificationErrorCode,
) => {
  try {
    await action();
  } catch (error) {
    expect(error).toBeInstanceOf(CloudRelayTicketVerificationError);
    expect((error as CloudRelayTicketVerificationError).code).toBe(code);
    return;
  }
  throw new Error(`Expected CloudRelayTicketVerificationError ${code}`);
};

const expectConfigError = (action: () => unknown) => {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(CloudRelayTicketVerificationError);
    expect((error as CloudRelayTicketVerificationError).code).toBe(
      "INVALID_VERIFIER_CONFIG",
    );
    return;
  }
  throw new Error("Expected INVALID_VERIFIER_CONFIG");
};

function createTestVerifier(
  keys: ReadonlyArray<{ kid: string; jwk: Record<string, unknown> }> = [
    { kid: KEY_ID, jwk: primary.publicJwk },
  ],
  overrides: Partial<CloudRelayTicketVerifierConfig> = {},
) {
  let calls = 0;
  const verifier = createCloudRelayTicketVerifier({
    jwksUrl: JWKS_URL,
    now: () => FIXED_NOW,
    fetchImpl: async (input, init) => {
      calls += 1;
      expect(String(input)).toBe(JWKS_URL);
      expect(init?.redirect).toBe("manual");
      expect(init?.cache).toBe("no-store");
      return new Response(JSON.stringify(jwks(keys)), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
    ...overrides,
  });
  return { verifier, calls: () => calls };
}

describe("Cloud Relay ticket verification", () => {
  it("returns only the verified transport identity for a locally signed canonical ticket", async () => {
    expect(MIRRORED_CLOUD_AUTH_CLAIMS_FIXTURE).toEqual({
      iss: "mira:cloud-auth",
      sub: ACCOUNT_ID,
      device_id: DEVICE_ID,
      aud: "mira:cloud-relay-transport",
      scope: ["relay:transport"],
      relay: { room: ROOM, role: "client" },
      iat: FIXED_NOW_SECONDS,
      nbf: FIXED_NOW_SECONDS,
      exp: FIXED_NOW_SECONDS + 300,
    });

    const ticket = await signTicket(primary.privateKey);
    const { verifier, calls } = createTestVerifier();
    const identity = await verifier.verify(ticket, roleContext());

    expect(identity).toEqual({
      accountId: ACCOUNT_ID,
      deviceId: DEVICE_ID,
      room: ROOM,
      role: "client",
      expiresAt: new Date((FIXED_NOW_SECONDS + 300) * 1000),
    });
    expect(Object.keys(identity).sort()).toEqual([
      "accountId",
      "deviceId",
      "expiresAt",
      "role",
      "room",
    ]);
    expect(Object.isFrozen(identity)).toBe(true);
    expect(JSON.stringify(identity)).not.toContain(ticket);
    expect(calls()).toBe(1);

    const maxTtlTicket = await signTicket(
      primary.privateKey,
      relayClaims({ exp: FIXED_NOW_SECONDS + 600 }),
    );
    expect((await verifier.verify(maxTtlTicket, roleContext())).accountId).toBe(
      ACCOUNT_ID,
    );
    expect(calls()).toBe(1);
  });

  it("does not log raw tickets or JWKS response bodies", async () => {
    const spies = [
      vi.spyOn(console, "log"),
      vi.spyOn(console, "info"),
      vi.spyOn(console, "warn"),
      vi.spyOn(console, "error"),
      vi.spyOn(console, "debug"),
    ];
    try {
      const ticket = await signTicket(primary.privateKey);
      const foreignTicket = await signTicket(other.privateKey);
      const { verifier } = createTestVerifier();
      await verifier.verify(ticket, roleContext());
      await expectVerificationError(
        () => verifier.verify(foreignTicket, roleContext()),
        "INVALID_SIGNATURE",
      );
      for (const spy of spies) expect(spy).not.toHaveBeenCalled();
    } finally {
      for (const spy of spies) spy.mockRestore();
    }
  });

  it("selects only the trusted key identified by the bounded kid header", async () => {
    const { verifier } = createTestVerifier([
      { kid: KEY_ID, jwk: primary.publicJwk },
      { kid: NEXT_KEY_ID, jwk: other.publicJwk },
    ]);

    const nextTicket = await signTicket(
      other.privateKey,
      relayClaims(),
      ticketHeader({ kid: NEXT_KEY_ID }),
    );
    expect((await verifier.verify(nextTicket, roleContext())).accountId).toBe(ACCOUNT_ID);

    const mismatchedKey = await signTicket(
      primary.privateKey,
      relayClaims(),
      ticketHeader({ kid: NEXT_KEY_ID }),
    );
    await expectVerificationError(
      () => verifier.verify(mismatchedKey, roleContext()),
      "INVALID_SIGNATURE",
    );
  });

  it("rejects malformed tokens, unsafe headers and token-selected key URLs before fetching", async () => {
    const { verifier, calls } = createTestVerifier();
    const valid = await signTicket(primary.privateKey);
    const [headerSegment, payloadSegment, signatureSegment] = valid.split(".");

    const cases: Array<[string, CloudRelayTicketVerificationErrorCode]> = [
      ["", "MALFORMED_TOKEN"],
      ["a".repeat(CLOUD_RELAY_TICKET_MAX_LENGTH + 1), "MALFORMED_TOKEN"],
      ["not-a-jwt", "MALFORMED_TOKEN"],
      [`${headerSegment}.${payloadSegment}`, "MALFORMED_TOKEN"],
      [`${headerSegment}.${payloadSegment}.${signatureSegment}.extra`, "MALFORMED_TOKEN"],
      [`${headerSegment}..${signatureSegment}`, "MALFORMED_TOKEN"],
      [manualToken(ticketHeader({ alg: "none" }), relayClaims()), "INVALID_HEADER"],
      [manualToken(ticketHeader({ alg: "HS256" }), relayClaims()), "INVALID_HEADER"],
      [manualToken(ticketHeader({ typ: "JWS" }), relayClaims()), "INVALID_HEADER"],
      [manualToken(ticketHeader({ kid: "" }), relayClaims()), "INVALID_HEADER"],
      [manualToken(ticketHeader({ kid: "a".repeat(65) }), relayClaims()), "INVALID_HEADER"],
      [
        manualToken(
          ticketHeader({ jku: "https://attacker.example/jwks.json" }),
          relayClaims(),
        ),
        "INVALID_HEADER",
      ],
      [
        manualToken(
          { alg: "EdDSA", kid: KEY_ID, typ: "JWT", jwk: { kty: "OKP" } },
          relayClaims(),
        ),
        "INVALID_HEADER",
      ],
      [manualToken({ alg: "EdDSA", typ: "JWT" }, relayClaims()), "INVALID_HEADER"],
    ];

    for (const [token, code] of cases) {
      await expectVerificationError(() => verifier.verify(token, roleContext()), code);
    }
    expect(calls()).toBe(0);
  });

  it("never falls back to legacy tokens or unsigned keys when JWKS is unavailable", async () => {
    const verifier = createCloudRelayTicketVerifier({
      jwksUrl: JWKS_URL,
      now: () => FIXED_NOW,
      fetchImpl: async () => new Response("", { status: 503 }),
    });

    const ticket = await signTicket(primary.privateKey);
    await expectVerificationError(
      () => verifier.verify("h".repeat(48), roleContext()),
      "MALFORMED_TOKEN",
    );
    await expectVerificationError(
      () => verifier.verify(ticket, roleContext()),
      "JWKS_UNAVAILABLE",
    );
  });

  it("rejects unknown keys and invalid signatures without leaking ticket material", async () => {
    const { verifier } = createTestVerifier();
    const unknownKid = await signTicket(
      primary.privateKey,
      relayClaims(),
      ticketHeader({ kid: "untrusted-key" }),
    );
    await expectVerificationError(
      () => verifier.verify(unknownKid, roleContext()),
      "UNKNOWN_KEY",
    );

    const foreignKey = await signTicket(other.privateKey);
    await expectVerificationError(
      () => verifier.verify(foreignKey, roleContext()),
      "INVALID_SIGNATURE",
    );

    const valid = await signTicket(primary.privateKey);
    const [headerSegment, , signatureSegment] = valid.split(".");
    const modifiedPayload = encodeSegment(
      JSON.stringify(relayClaims({ sub: "another-account" })),
    );
    await expectVerificationError(
      () =>
        verifier.verify(
          `${headerSegment}.${modifiedPayload}.${signatureSegment}`,
          roleContext(),
        ),
      "INVALID_SIGNATURE",
    );

    try {
      await verifier.verify(foreignKey, roleContext());
    } catch (error) {
      expect((error as Error).message).not.toContain(foreignKey);
    }
  });

  it("rejects every non-canonical claim shape and wrong room or role", async () => {
    const { verifier } = createTestVerifier();
    const claimsCases: Array<[Record<string, unknown>, CloudRelayTicketVerificationErrorCode]> = [
      [relayClaims({ iss: "mira:other-issuer" }), "ISSUER_MISMATCH"],
      [relayClaims({ aud: "mira:cloud-shiyan" }), "AUDIENCE_MISMATCH"],
      [relayClaims({ scope: [] }), "INVALID_CLAIMS"],
      [relayClaims({ scope: ["other:scope"] }), "INVALID_CLAIMS"],
      [relayClaims({ scope: ["relay:transport", "remote:terminal"] }), "INVALID_CLAIMS"],
      [relayClaims({ device_id: undefined }), "INVALID_CLAIMS"],
      [relayClaims({ sub: "" }), "INVALID_CLAIMS"],
      [relayClaims({ sub: "a".repeat(129) }), "INVALID_CLAIMS"],
      [relayClaims({ relay: undefined }), "INVALID_CLAIMS"],
      [relayClaims({ relay: { room: "room 7f3a", role: "client" } }), "INVALID_CLAIMS"],
      [relayClaims({ relay: { room: ROOM, role: "owner" } }), "INVALID_CLAIMS"],
      [relayClaims({ relay: { room: ROOM, role: "client", tools: [] } }), "INVALID_CLAIMS"],
      [relayClaims({ tools: ["terminal"] }), "INVALID_CLAIMS"],
      [
        relayClaims({
          nbf: FIXED_NOW_SECONDS - 1,
          exp: FIXED_NOW_SECONDS + 300,
        }),
        "INVALID_CLAIMS",
      ],
      [
        relayClaims({
          iat: FIXED_NOW_SECONDS,
          nbf: FIXED_NOW_SECONDS + 10,
          exp: FIXED_NOW_SECONDS + 10,
        }),
        "INVALID_CLAIMS",
      ],
      [relayClaims({ exp: FIXED_NOW_SECONDS + 300.5 }), "INVALID_CLAIMS"],
      [
        relayClaims({
          iat: FIXED_NOW_SECONDS + 30,
          nbf: FIXED_NOW_SECONDS + 30,
          exp: FIXED_NOW_SECONDS + 330,
        }),
        "IAT_IN_FUTURE",
      ],
      [
        relayClaims({
          nbf: FIXED_NOW_SECONDS + 30,
          exp: FIXED_NOW_SECONDS + 330,
        }),
        "NOT_YET_VALID",
      ],
      [
        relayClaims({
          iat: FIXED_NOW_SECONDS - 300,
          nbf: FIXED_NOW_SECONDS - 300,
          exp: FIXED_NOW_SECONDS - 1,
        }),
        "EXPIRED",
      ],
      [relayClaims({ exp: FIXED_NOW_SECONDS + 601 }), "TTL_EXCEEDED"],
    ];

    for (const [claims, code] of claimsCases) {
      const ticket = await signTicket(primary.privateKey, claims);
      await expectVerificationError(() => verifier.verify(ticket, roleContext()), code);
    }

    const valid = await signTicket(primary.privateKey);
    await expectVerificationError(
      () => verifier.verify(valid, { room: "room-other", role: "client" }),
      "RELAY_CONTEXT_MISMATCH",
    );
    await expectVerificationError(
      () => verifier.verify(valid, { room: ROOM, role: "host" }),
      "RELAY_CONTEXT_MISMATCH",
    );
  });

  it("allows bounded clock skew but rejects an invalid verifier clock", async () => {
    const expired = relayClaims({
      iat: FIXED_NOW_SECONDS - 300,
      nbf: FIXED_NOW_SECONDS - 300,
      exp: FIXED_NOW_SECONDS - 1,
    });
    const ticket = await signTicket(primary.privateKey, expired);
    const { verifier } = createTestVerifier(undefined, { clockSkewSeconds: 5 });
    expect((await verifier.verify(ticket, roleContext())).accountId).toBe(ACCOUNT_ID);

    const invalidClock = createTestVerifier(undefined, {
      now: () => new Date(Number.NaN),
    });
    const validTicket = await signTicket(primary.privateKey);
    await expectVerificationError(
      () => invalidClock.verifier.verify(validTicket, roleContext()),
      "INVALID_VERIFIER_CONFIG",
    );
  });

  it("fails closed on unsafe configuration and missing connection context", async () => {
    expectConfigError(() =>
      createCloudRelayTicketVerifier({
        jwksUrl: "http://auth.example.com/.well-known/jwks.json",
      }),
    );
    expectConfigError(() =>
      createCloudRelayTicketVerifier({ jwksUrl: "https://user:pass@auth.example.com/jwks" }),
    );
    expectConfigError(() =>
      createCloudRelayTicketVerifier({ jwksUrl: "https://auth.example.com/jwks?next=evil" }),
    );
    for (const config of [
      { jwksUrl: JWKS_URL, clockSkewSeconds: 61 },
      { jwksUrl: JWKS_URL, clockSkewSeconds: -1 },
      { jwksUrl: JWKS_URL, jwksCacheSeconds: 0 },
      { jwksUrl: JWKS_URL, jwksCacheSeconds: 301 },
    ]) {
      expectConfigError(() => createCloudRelayTicketVerifier(config));
    }

    const { verifier, calls } = createTestVerifier();
    await expectVerificationError(
      () => verifier.verify("unused", {} as never),
      "INVALID_VERIFIER_CONFIG",
    );
    expect(calls()).toBe(0);
  });
});
