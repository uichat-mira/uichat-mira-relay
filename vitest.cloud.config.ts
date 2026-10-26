import { generateKeyPairSync } from "node:crypto";
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

// Ephemeral test keys exist only in this Miniflare instance, never in prod.
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const jwk = publicKey.export({ format: "jwk" });
const jwks = JSON.stringify({
  keys: [{ ...jwk, kid: "rel004-test-key", use: "sig", alg: "EdDSA" }],
});

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
          RELAY_JWKS_SERVICE(request) {
            if (new URL(request.url).toString() !==
              "https://auth.test/.well-known/jwks.json") {
              return new Response(null, { status: 404 });
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
