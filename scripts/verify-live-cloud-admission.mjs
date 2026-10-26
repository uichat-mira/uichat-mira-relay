#!/usr/bin/env node
// REL-005: explicit opt-in live Cloud Auth -> Relay T3 transport probe.
// No credentials, rooms or JWTs are printed, persisted or sent to GitHub.
import { createPublicKey, verify as verifySignature } from "node:crypto";
import { strict as assert } from "node:assert";

const AUDIENCE = "mira:cloud-relay-transport";
const ROOM_PATTERN = /^[A-Za-z0-9_-]{16,128}$/u;
const TIMEOUT_MS = 10_000;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function origin(name, scheme) {
  const input = process.env[name];
  assert(input, name + " is required");
  const url = new URL(input);
  assert(url.protocol === scheme && !url.username && !url.password &&
    (url.pathname === "/" || url.pathname === "") &&
    !url.search && !url.hash, name + " must be a bare " + scheme + "// origin");
  return url.origin;
}

function config() {
  const auth = origin("REL005_AUTH_ORIGIN", "https:");
  const relay = origin("REL005_RELAY_ORIGIN", "wss:");
  assert(new URL(relay).hostname !== "relay.tomz.io",
    "Live probe must not target the Legacy production Relay");
  const room = process.env.REL005_ROOM;
  assert(ROOM_PATTERN.test(room || ""), "REL005_ROOM is invalid");
  for (const name of ["REL005_HOST_SESSION", "REL005_CLIENT_SESSION", "REL005_FOREIGN_SESSION"]) {
    assert(process.env[name], name + " is required; sessions must be device-bound and distinct");
  }
  return { auth, relay, room };
}

function errorCode(payload) {
  const code = payload && payload.error && payload.error.code;
  return typeof code === "string" && /^[A-Z0-9_]{3,80}$/u.test(code) ? code : "INVALID_ERROR";
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    redirect: "manual",
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json") ?
    await response.json().catch(() => null) : null;
  return { status: response.status, body, contentType };
}

async function jwks(auth) {
  const response = await requestJson(auth + "/.well-known/jwks.json", {
    headers: { accept: "application/json" },
  });
  assert.equal(response.status, 200, "JWKS must return 200 from the HTTPS API ingress");
  assert(Array.isArray(response.body?.keys) &&
    response.body.keys.length >= 1 && response.body.keys.length <= 8,
    "JWKS must expose 1–8 public keys (not Portal HTML)");
  const keys = new Map();
  for (const key of response.body.keys) {
    assert.deepEqual(Object.keys(key).sort(),
      ["alg", "crv", "kid", "kty", "use", "x"].sort(), "unexpected JWKS shape");
    assert(key.kty === "OKP" && key.crv === "Ed25519" &&
      key.alg === "EdDSA" && key.use === "sig", "invalid public JWKS key");
    assert(typeof key.kid === "string" && !keys.has(key.kid), "duplicate or absent JWKS kid");
    keys.set(key.kid, createPublicKey({ key, format: "jwk" }));
  }
  return keys;
}

function verifyTicket(token, keys, expected) {
  assert(typeof token === "string" && token.length <= 8192,
    "credential is not a bounded compact JWT");
  const parts = token.split(".");
  assert.equal(parts.length, 3, "credential is not compact JWS");
  const [headerSegment, payloadSegment, signatureSegment] = parts;
  const header = JSON.parse(Buffer.from(headerSegment, "base64url").toString("utf8"));
  const claims = JSON.parse(Buffer.from(payloadSegment, "base64url").toString("utf8"));
  assert.deepEqual(Object.keys(header).sort(), ["alg", "kid", "typ"], "JWT header shape");
  assert.equal(header.alg, "EdDSA");
  assert.equal(header.typ, "JWT");
  assert(keys.has(header.kid), "ticket kid missing from trusted JWKS");
  assert(verifySignature(null, Buffer.from(headerSegment + "." + payloadSegment, "ascii"),
    keys.get(header.kid), Buffer.from(signatureSegment, "base64url")),
  "Node signer ticket signature failed against public HTTPS JWKS");
  assert.equal(claims.iss, "mira:cloud-auth");
  assert.equal(claims.aud, AUDIENCE);
  assert.deepEqual(claims.scope, ["relay:transport"]);
  assert.equal(claims.relay?.room, expected.room);
  assert.equal(claims.relay?.role, expected.role);
  assert(typeof claims.sub === "string" && claims.sub.length > 0);
  assert(typeof claims.device_id === "string" && claims.device_id.length > 0);
  assert(Number.isInteger(claims.exp) && claims.exp > Date.now() / 1000);
  assert(Number.isInteger(claims.iat) && claims.exp - claims.iat <= 600);
  return claims;
}

async function issue(auth, session, room, role, expectedStatus = 200) {
  const result = await requestJson(auth + "/v1/service-credentials", {
    method: "POST",
    headers: {
      authorization: "Bearer " + session,
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify({ audience: AUDIENCE, relay: { room, role } }),
  });
  assert.equal(result.status, expectedStatus, "Cloud Auth issuance HTTP status differed");
  if (expectedStatus !== 200) {
    assert.equal(errorCode(result.body), "SERVICE_CREDENTIAL_RELAY_NOT_AUTHORIZED",
      "expected the uniform server-side room/role entitlement denial");
    return null;
  }
  assert.equal(result.body?.tokenType, "Bearer");
  assert.equal(result.body?.audience, AUDIENCE);
  assert(typeof result.body?.token === "string", "no token in issuance response");
  return result.body.token;
}


async function issueShiyan(auth, session) {
  const result = await requestJson(auth + "/v1/service-credentials", {
    method: "POST",
    headers: {
      authorization: "Bearer " + session,
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify({ audience: "mira:cloud-shiyan" }),
  });
  assert.equal(result.status, 200, "Shiyan credential issuance failed");
  assert.equal(result.body?.audience, "mira:cloud-shiyan");
  return result.body?.token;
}

function otherRoom(room) {
  return room.slice(0, -1) + (room.endsWith("A") ? "B" : "A");
}

function peer(url) {
  const socket = new WebSocket(url);
  const queued = [];
  const waiting = [];
  let closed = null;
  let closeWaiter = null;
  socket.addEventListener("message", (event) => {
    let value;
    try { value = JSON.parse(event.data); } catch { value = { type: "malformed" }; }
    if (waiting.length) waiting.shift()(value);
    else queued.push(value);
  });
  socket.addEventListener("close", (event) => {
    closed = event.code;
    if (closeWaiter) closeWaiter(event.code);
  });
  return {
    open: () => new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("WebSocket open timeout")), TIMEOUT_MS);
      socket.addEventListener("open", () => { clearTimeout(timer); resolve(); }, { once: true });
      socket.addEventListener("error", () => { clearTimeout(timer); reject(new Error("WebSocket connect failed")); }, { once: true });
    }),
    send: (frame) => socket.send(JSON.stringify({ version: 1, ...frame })),
    next: () => new Promise((resolve, reject) => {
      if (queued.length) return resolve(queued.shift());
      const timer = setTimeout(() => {
        const index = waiting.indexOf(onMessage);
        if (index !== -1) waiting.splice(index, 1);
        reject(new Error("WebSocket frame timeout"));
      }, TIMEOUT_MS);
      function onMessage(value) { clearTimeout(timer); resolve(value); }
      waiting.push(onMessage);
    }),
    closeCode: () => new Promise((resolve, reject) => {
      if (closed !== null) return resolve(closed);
      const timer = setTimeout(() => reject(new Error("WebSocket close timeout")), TIMEOUT_MS);
      closeWaiter = (code) => { clearTimeout(timer); resolve(code); };
    }),
    close: () => { if (socket.readyState === WebSocket.OPEN) socket.close(1000); },
  };
}

async function connect(relay, room, role, token) {
  const socket = peer(relay + "/v1/relay/" + encodeURIComponent(room) + "/socket");
  await socket.open();
  socket.send({ type: "hello", role, relayId: room, token });
  return socket;
}

async function acknowledged(socket, role, room) {
  const message = await socket.next();
  assert.equal(message.type, "hello_ack");
  assert.equal(message.role, role);
  assert.equal(message.relayId, room);
  assert.equal(message.protocolVersion, 1);
}

async function rejected(socket, code = "CLOUD_TICKET_REJECTED") {
  const frame = await socket.next();
  assert.equal(frame.type, "error");
  assert.equal(frame.code, code);
  assert.equal(await socket.closeCode(), 1008);
}

async function run() {
  const cfg = config();
  const sockets = [];
  try {
    const publicKeys = await jwks(cfg.auth);
    console.log("JWKS HTTPS ingress: public Ed25519 keys verified");
    const hostToken = await issue(cfg.auth, process.env.REL005_HOST_SESSION, cfg.room, "host");
    const clientToken = await issue(cfg.auth, process.env.REL005_CLIENT_SESSION, cfg.room, "client");
    const hostClaims = verifyTicket(hostToken, publicKeys, { room: cfg.room, role: "host" });
    const clientClaims = verifyTicket(clientToken, publicKeys, { room: cfg.room, role: "client" });
    assert.equal(hostClaims.sub, clientClaims.sub, "Host and Client must belong to one Cloud account");
    assert.notEqual(hostClaims.device_id, clientClaims.device_id, "different devices required");
    console.log("Real Cloud Auth issuer: valid signed Host/Client tickets verified");
    await issue(cfg.auth, process.env.REL005_FOREIGN_SESSION, cfg.room, "client", 403);
    await issue(cfg.auth, process.env.REL005_CLIENT_SESSION, cfg.room, "host", 403);
    await issue(cfg.auth, process.env.REL005_CLIENT_SESSION, otherRoom(cfg.room), "client", 403);
    console.log("Issuance authorization: foreign account, mobile-as-host, wrong room denied");
    const host = await connect(cfg.relay, cfg.room, "host", hostToken);
    sockets.push(host); await acknowledged(host, "host", cfg.room);
    const client = await connect(cfg.relay, cfg.room, "client", clientToken);
    sockets.push(client); await acknowledged(client, "client", cfg.room);
    const crossRole = await connect(cfg.relay, cfg.room, "host", clientToken);
    sockets.push(crossRole); await rejected(crossRole);
    const crossRoom = await connect(cfg.relay, otherRoom(cfg.room), "client", clientToken);
    sockets.push(crossRoom); await rejected(crossRoom);
    const shiyan = await issueShiyan(cfg.auth, process.env.REL005_CLIENT_SESSION);
    const crossAudience = await connect(cfg.relay, cfg.room, "client", shiyan);
    sockets.push(crossAudience); await rejected(crossAudience);
    const legacyToken = await connect(cfg.relay, cfg.room, "client", "c".repeat(48));
    sockets.push(legacyToken); await rejected(legacyToken);
    console.log("Real Worker/DO WebSocket: Host/Client ack; room/role/audience/Legacy token denied");
    client.send({ type: "request", requestId: "rel005-forward", path: "/remote/v1/manifest" });
    const forwarded = await host.next();
    assert.equal(forwarded.type, "request");
    assert(forwarded.requestId.endsWith("~rel005-forward"));
    host.send({ type: "complete", requestId: forwarded.requestId });
    assert.deepEqual(await client.next(), { version: 1, type: "complete", requestId: "rel005-forward" });
    client.send({ type: "request", requestId: "rel005-cancel", path: "/remote/v1/manifest" });
    const pending = await host.next();
    client.send({ type: "cancel", requestId: "rel005-cancel" });
    assert.deepEqual(await host.next(), { version: 1, type: "cancel", requestId: pending.requestId });
    console.log("Real Worker/DO transport: forward/complete/cancel verified");
    if (process.argv.includes("--expiry")) {
      const delayMs = Math.max(0, (clientClaims.exp + 1) * 1000 - Date.now());
      await sleep(delayMs);
      client.send({ type: "request", requestId: "rel005-after-exp", path: "/remote/v1/manifest" });
      const continued = await host.next();
      assert(continued.requestId.endsWith("~rel005-after-exp"));
      host.send({ type: "complete", requestId: continued.requestId });
      assert.equal((await client.next()).type, "complete");
      const expired = await connect(cfg.relay, cfg.room, "client", clientToken);
      sockets.push(expired); await rejected(expired);
      console.log("Expiry: healthy socket survived; reconnect rejected stale ticket");
    } else {
      console.log("Expiry past actual TTL: NOT RUN (use --expiry in a controlled window)");
    }
    console.log("REL-005 live transport probe: PASS (synthetic Host, not Desktop/phone E2E)");
  } finally {
    for (const socket of sockets) socket.close();
  }
}

run().catch((error) => {
  // Do not echo server bodies, JWTs, Sessions, socket URLs or stack traces.
  console.error("REL-005 probe failed: " +
    (error instanceof Error ? error.message.replace(/Bearer\s+\S+/gu, "Bearer [REDACTED]") : "unknown"));
  process.exitCode = 1;
});
