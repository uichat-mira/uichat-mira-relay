import { beforeAll, describe, expect, it } from "vitest";
import { createCloudRelayJwksCache } from "../src/cloud-relay-jwks.js";
import {
  createCloudRelayTicketVerifier,
  type CloudRelayTicketVerifierConfig,
} from "../src/cloud-relay-verifier.js";
import {
  CLOUD_AUTH_JWKS_CACHE_SECONDS,
  CLOUD_AUTH_JWKS_MAX_BYTES,
  CLOUD_AUTH_JWKS_MAX_KEYS,
  CloudRelayTicketVerificationError,
  type CloudRelayTicketVerificationErrorCode,
} from "../src/cloud-relay-ticket.js";
import {
  FIXED_NOW,
  KEY_ID,
  NEXT_KEY_ID,
  createSigningFixture,
  jwks,
  relayClaims,
  roleContext,
  signTicket,
  ticketHeader,
} from "./cloud-relay-fixtures.js";

const JWKS_URL = "https://auth.example.com/.well-known/jwks.json";

type SigningFixture = Awaited<ReturnType<typeof createSigningFixture>>;
let active: SigningFixture;
let next: SigningFixture;

beforeAll(async () => {
  active = await createSigningFixture(KEY_ID);
  next = await createSigningFixture(NEXT_KEY_ID);
});

const expectCacheError = async (
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

const jwksResponse = (body: unknown, status = 200) =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

function createCountingFetch(getBody: () => unknown, status = 200) {
  let calls = 0;
  const fetchImpl: typeof fetch = async (input, init) => {
    calls += 1;
    expect(String(input)).toBe(JWKS_URL);
    expect(init?.method).toBe("GET");
    expect(init?.redirect).toBe("manual");
    // Construct a genuine Workerd Request instead of trusting the fake fetch.
    expect(new Request(String(input), init).redirect).toBe("manual");
    expect(init?.cache).toBe("no-store");
    return jwksResponse(getBody(), status);
  };
  return { fetchImpl, calls: () => calls };
}

describe("Trusted Cloud Auth JWKS cache", () => {
  it("defaults to the published 300 second cache lifetime", () => {
    const cache = createCloudRelayJwksCache({ jwksUrl: JWKS_URL });
    expect(cache.maxAgeSeconds).toBe(CLOUD_AUTH_JWKS_CACHE_SECONDS);

    const bounded = createCloudRelayJwksCache({
      jwksUrl: JWKS_URL,
      maxAgeSeconds: 300,
    });
    expect(bounded.maxAgeSeconds).toBe(300);

    for (const maxAgeSeconds of [0, 301]) {
      expect(() =>
        createCloudRelayJwksCache({ jwksUrl: JWKS_URL, maxAgeSeconds }),
      ).toThrow(CloudRelayTicketVerificationError);
    }
  });

  it("uses a Workerd-supported request mode and refuses an HTTP redirect", async () => {
    // Workerd's native Request constructor rejects redirect: "error".
    const nativeRequest = new Request(JWKS_URL, {
      method: "GET",
      redirect: "manual",
      cache: "no-store",
    });
    expect(nativeRequest.redirect).toBe("manual");

    const cache = createCloudRelayJwksCache({
      jwksUrl: JWKS_URL,
      fetchImpl: async (_input, init) => {
        expect(new Request(JWKS_URL, init).redirect).toBe("manual");
        return new Response(null, {
          status: 302,
          headers: { location: "https://untrusted.example/jwks.json" },
        });
      },
    });
    await expectCacheError(() => cache.getKey(KEY_ID), "JWKS_UNAVAILABLE");
  });

  it("fails closed and releases in-flight waiters when JWKS headers never arrive", async () => {
    let aborted = false;
    let mode: "hang" | "ok" = "hang";
    const cache = createCloudRelayJwksCache({
      jwksUrl: JWKS_URL,
      requestTimeoutMs: 30,
      fetchImpl: async (_input, init) => {
        if (mode === "ok") {
          return jwksResponse(jwks([{ kid: KEY_ID, jwk: active.publicJwk }]));
        }
        init?.signal?.addEventListener("abort", () => { aborted = true; }, { once: true });
        // The timeout must settle even if a transport ignores AbortSignal.
        return new Promise<Response>(() => undefined);
      },
    });
    await expectCacheError(() => cache.getKey(KEY_ID), "JWKS_UNAVAILABLE");
    expect(aborted).toBe(true);
    mode = "ok";
    expect(await cache.getKey(KEY_ID)).toBeDefined();
  });

  it("applies the same deadline while reading a stalled JWKS response body", async () => {
    let aborted = false;
    const cache = createCloudRelayJwksCache({
      jwksUrl: JWKS_URL,
      requestTimeoutMs: 30,
      fetchImpl: async (_input, init) => {
        init?.signal?.addEventListener("abort", () => { aborted = true; }, { once: true });
        return new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(new TextEncoder().encode('{"keys":['));
              // Deliberately never finish the response body.
            },
          }),
          { status: 200 },
        );
      },
    });
    await expectCacheError(() => cache.getKey(KEY_ID), "JWKS_UNAVAILABLE");
    expect(aborted).toBe(true);
  });

  it("rejects invalid request timeout configuration without fetching", () => {
    for (const requestTimeoutMs of [0, -1, 10_001, 1.5, Number.NaN]) {
      expect(() => createCloudRelayJwksCache({
        jwksUrl: JWKS_URL,
        requestTimeoutMs,
      })).toThrow(CloudRelayTicketVerificationError);
    }
  });

  it("reuses a fresh key set and refreshes only after the cache bound", async () => {
    let clock = FIXED_NOW.getTime();
    const { fetchImpl, calls } = createCountingFetch(() => jwks([
      { kid: KEY_ID, jwk: active.publicJwk },
    ]));
    const cache = createCloudRelayJwksCache({
      jwksUrl: JWKS_URL,
      fetchImpl,
      now: () => clock,
    });

    await cache.getKey(KEY_ID);
    expect(calls()).toBe(1);

    clock += 299_000;
    await cache.getKey(KEY_ID);
    expect(calls()).toBe(1);

    clock += 1_000;
    await cache.getKey(KEY_ID);
    expect(calls()).toBe(2);
  });

  it("fails an unknown kid without fetching again or trusting a token-selected URL", async () => {
    let clock = FIXED_NOW.getTime();
    const { fetchImpl, calls } = createCountingFetch(() => jwks([
      { kid: KEY_ID, jwk: active.publicJwk },
    ]));
    const cache = createCloudRelayJwksCache({
      jwksUrl: JWKS_URL,
      fetchImpl,
      now: () => clock,
    });

    await cache.getKey(KEY_ID);
    await expectCacheError(() => cache.getKey("attacker-key"), "UNKNOWN_KEY");
    expect(calls()).toBe(1);

    clock += 301_000;
    await cache.getKey(KEY_ID);
    expect(calls()).toBe(2);
  });

  it("supports pre-published next keys and retires old keys after refresh", async () => {
    let clock = FIXED_NOW.getTime();
    let published = [active];
    const { fetchImpl, calls } = createCountingFetch(() =>
      jwks(published.map((key) => ({ kid: key.keyId, jwk: key.publicJwk }))),
    );
    const verifier = createCloudRelayTicketVerifier({
      jwksUrl: JWKS_URL,
      fetchImpl,
      now: () => new Date(clock),
      jwksCacheSeconds: 1,
    });

    const oldTicket = await signTicket(
      active.privateKey,
      relayClaims(),
      ticketHeader({ kid: KEY_ID }),
    );
    const newTicket = await signTicket(
      next.privateKey,
      relayClaims(),
      ticketHeader({ kid: NEXT_KEY_ID }),
    );

    await verifier.verify(oldTicket, roleContext());
    expect(calls()).toBe(1);

    await expectCacheError(
      () => verifier.verify(newTicket, roleContext()),
      "UNKNOWN_KEY",
    );
    expect(calls()).toBe(1);

    published = [active, next];
    clock += 2_000;
    await verifier.verify(newTicket, roleContext());
    expect(calls()).toBe(2);
    await verifier.verify(oldTicket, roleContext());
    expect(calls()).toBe(2);

    published = [next];
    clock += 2_000;
    await expectCacheError(
      () => verifier.verify(oldTicket, roleContext()),
      "UNKNOWN_KEY",
    );
    expect(calls()).toBe(3);
    await verifier.verify(newTicket, roleContext());
    expect(calls()).toBe(3);
  });

  it("fails closed on unreachable, non-2xx or malformed JWKS after the cache expires", async () => {
    let clock = FIXED_NOW.getTime();
    let mode: "ok" | "throw" | "status" | "json" = "ok";
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls += 1;
      if (mode === "throw") throw new Error("network down");
      if (mode === "status") return jwksResponse("", 503);
      if (mode === "json") return jwksResponse("{");
      return jwksResponse(jwks([{ kid: KEY_ID, jwk: active.publicJwk }]));
    };
    const cache = createCloudRelayJwksCache({
      jwksUrl: JWKS_URL,
      fetchImpl,
      now: () => clock,
    });

    await cache.getKey(KEY_ID);
    expect(calls).toBe(1);

    clock += 301_000;
    mode = "throw";
    await expectCacheError(() => cache.getKey(KEY_ID), "JWKS_UNAVAILABLE");
    expect(calls).toBe(2);

    mode = "status";
    await expectCacheError(() => cache.getKey(KEY_ID), "JWKS_UNAVAILABLE");
    expect(calls).toBe(3);

    mode = "json";
    await expectCacheError(() => cache.getKey(KEY_ID), "JWKS_INVALID");
    expect(calls).toBe(4);

    mode = "ok";
    await cache.getKey(KEY_ID);
    expect(calls).toBe(5);
  });

  it("rejects malformed, duplicate, non-Ed25519, empty and oversized key sets", async () => {
    const valid = {
      kty: "OKP",
      crv: "Ed25519",
      use: "sig",
      alg: "EdDSA",
      kid: KEY_ID,
      x: active.publicJwk.x,
    };
    const bodies: unknown[] = [
      {},
      { keys: [] },
      { keys: [valid], extra: true },
      { keys: [{ ...valid, kty: "RSA" }] },
      { keys: [{ ...valid, crv: "X25519" }] },
      { keys: [{ ...valid, alg: "ES256" }] },
      { keys: [{ ...valid, use: "enc" }] },
      { keys: [{ ...valid, kid: "" }] },
      { keys: [{ ...valid, x: "short" }] },
      { keys: [{ ...valid, extra: "field" }] },
      { keys: [valid, { ...valid }] },
      {
        keys: Array.from({ length: CLOUD_AUTH_JWKS_MAX_KEYS + 1 }, (_, index) => ({
          ...valid,
          kid: `key-${index}`,
        })),
      },
      "x".repeat(CLOUD_AUTH_JWKS_MAX_BYTES + 1),
    ];

    for (const body of bodies) {
      const { fetchImpl } = createCountingFetch(() => body);
      const cache = createCloudRelayJwksCache({
        jwksUrl: JWKS_URL,
        fetchImpl,
      });
      await expectCacheError(() => cache.getKey(KEY_ID), "JWKS_INVALID");
    }
  });

  it("coalesces concurrent cache misses into one bounded fetch", async () => {
    let resolveFetch!: (response: Response) => void;
    let calls = 0;
    const pending = new Promise<Response>((resolve) => {
      resolveFetch = resolve;
    });
    const fetchImpl: typeof fetch = () => {
      calls += 1;
      return pending;
    };
    const cache = createCloudRelayJwksCache({ jwksUrl: JWKS_URL, fetchImpl });

    const first = cache.getKey(KEY_ID);
    const second = cache.getKey(KEY_ID);
    expect(calls).toBe(1);

    resolveFetch(
      jwksResponse(jwks([{ kid: KEY_ID, jwk: active.publicJwk }])),
    );
    await Promise.all([first, second]);
    expect(calls).toBe(1);
  });

  it("fails closed when the verifier clock is invalid", async () => {
    const { fetchImpl, calls } = createCountingFetch(() => jwks([]));
    const cache = createCloudRelayJwksCache({
      jwksUrl: JWKS_URL,
      fetchImpl,
      now: () => Number.NaN,
    });
    await expectCacheError(
      () => cache.getKey(KEY_ID),
      "INVALID_VERIFIER_CONFIG",
    );
    expect(calls()).toBe(0);
  });

  it("does not accept a JWKS origin other than the configured HTTPS URL", () => {
    const invalidConfigs: CloudRelayTicketVerifierConfig[] = [
      { jwksUrl: "http://auth.example.com/.well-known/jwks.json" },
      { jwksUrl: "https://user:secret@auth.example.com/jwks" },
      { jwksUrl: "https://auth.example.com/jwks#fragment" },
      { jwksUrl: "https://auth.example.com/jwks?key=token" },
    ];
    for (const config of invalidConfigs) {
      expect(() => createCloudRelayTicketVerifier(config)).toThrow(
        CloudRelayTicketVerificationError,
      );
    }
  });
});
