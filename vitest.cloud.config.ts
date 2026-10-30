import { generateKeyPairSync } from "node:crypto";
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

// Ephemeral test keys exist only in this Miniflare instance, never in prod.
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const jwk = publicKey.export({ format: "jwk" });
const jwks = JSON.stringify({
  keys: [{ ...jwk, kid: "rel004-test-key", use: "sig", alg: "EdDSA" }],
});

// Test-only gate: pause the JWKS service response until the socket has
// received its second frame. No production binding or delay is introduced.
const jwksGate: {
  blocking: boolean;
  entered: boolean;
  release: (() => void) | null;
} = { blocking: false, entered: false, release: null };

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          RELAY_ADMISSION_MODE: "cloud",
          CLOUD_AUTH_JWKS_URL: "https://auth.test/.well-known/jwks.json",
          TEST_SIGNING_PRIVATE_JWK: JSON.stringify(privateKey.export({ format: "jwk" })),
        },
        serviceBindings: {
          async RELAY_JWKS_SERVICE(request) {
            const url = new URL(request.url);
            if (url.origin !== "https://auth.test") {
              return new Response(null, { status: 404 });
            }

            if (request.method === "POST" && url.pathname === "/__test/jwks/hold") {
              if (jwksGate.blocking) return new Response(null, { status: 409 });
              jwksGate.blocking = true;
              jwksGate.entered = false;
              return new Response(null, { status: 204 });
            }
            if (request.method === "GET" && url.pathname === "/__test/jwks/status") {
              return Response.json({ entered: jwksGate.entered });
            }
            if (request.method === "POST" && url.pathname === "/__test/jwks/release") {
              jwksGate.blocking = false;
              jwksGate.release?.();
              jwksGate.release = null;
              return new Response(null, { status: 204 });
            }
            if (request.method !== "GET" || url.pathname !== "/.well-known/jwks.json") {
              return new Response(null, { status: 404 });
            }
            if (jwksGate.blocking) {
              jwksGate.entered = true;
              await new Promise<void>((resolve) => { jwksGate.release = resolve; });
            }
            return new Response(jwks, {
              headers: { "content-type": "application/json" },
            });
          },
        },
      },
    }),
  ],
  test: {
    include: ["test/cloud-room-socket.test.ts"],
    fileParallelism: false,
  },
});
