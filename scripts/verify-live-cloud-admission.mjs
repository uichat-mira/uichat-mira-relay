#!/usr/bin/env node
// REL-005: explicit opt-in live Cloud Auth -> Relay T3 transport probe.
// No credentials, rooms or JWTs are printed, persisted or sent to GitHub.
import {
  RELAY_AUDIENCE,
  ProbeError,
  errorCode,
  fail,
  failureCategory,
  importJwks,
  parseProbeConfig,
  redactDiagnostic,
  verifyShiyanClaims,
  verifyTicket,
} from "./cloud-probe-contract.mjs";

const TIMEOUT_MS = 10_000;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    redirect: "manual",
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json") ?
    await response.json().catch(() => null) : null;
  return { status: response.status, body };
}

async function fetchJwks(auth) {
  let response;
  try {
    response = await requestJson(auth + "/.well-known/jwks.json", {
      headers: { accept: "application/json" },
    });
  } catch {
    fail("JWKS", "JWKS HTTPS request failed");
  }
  if (response.status !== 200) {
    fail("JWKS", "JWKS must return 200 from the HTTPS API ingress");
  }
  return importJwks(response.body);
}

async function issue(auth, session, room, role, expectedStatus = 200) {
  let result;
  try {
    result = await requestJson(auth + "/v1/service-credentials", {
      method: "POST",
      headers: {
        authorization: "Bearer " + session,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({ audience: RELAY_AUDIENCE, relay: { room, role } }),
    });
  } catch {
    fail("ISSUANCE", "Cloud Auth issuance request failed");
  }
  if (result.status !== expectedStatus) {
    fail("ISSUANCE", "Cloud Auth issuance HTTP status differed");
  }
  if (expectedStatus !== 200) {
    if (errorCode(result.body) !== "SERVICE_CREDENTIAL_RELAY_NOT_AUTHORIZED") {
      fail("ISSUANCE", "expected the uniform server-side room/role entitlement denial");
    }
    return null;
  }
  if (result.body?.tokenType !== "Bearer" ||
    result.body?.audience !== RELAY_AUDIENCE ||
    typeof result.body?.token !== "string") {
    fail("ISSUANCE", "Cloud Auth issuance response shape differed");
  }
  return result.body.token;
}

async function issueShiyan(auth, session) {
  let result;
  try {
    result = await requestJson(auth + "/v1/service-credentials", {
      method: "POST",
      headers: {
        authorization: "Bearer " + session,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({ audience: "mira:cloud-shiyan" }),
    });
  } catch {
    fail("ISSUANCE", "Shiyan credential issuance request failed");
  }
  if (result.status !== 200 ||
    result.body?.audience !== "mira:cloud-shiyan" ||
    typeof result.body?.token !== "string") {
    fail("ISSUANCE", "Shiyan credential issuance failed");
  }
  return result.body.token;
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
      socket.addEventListener("error", () => {
        clearTimeout(timer);
        reject(new Error("WebSocket connect failed"));
      }, { once: true });
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

function acknowledged(socket, role, room) {
  return socket.next().then((message) => {
    if (message.type !== "hello_ack" ||
      message.role !== role ||
      message.relayId !== room ||
      message.protocolVersion !== 1) {
      fail("ADMISSION", "Relay hello_ack contract differed");
    }
  });
}

async function rejected(socket, code = "CLOUD_TICKET_REJECTED") {
  const frame = await socket.next();
  if (frame.type !== "error" || frame.code !== code) {
    fail("ADMISSION", "Relay admission denial contract differed");
  }
  if (await socket.closeCode() !== 1008) {
    fail("ADMISSION", "Relay denial close code differed");
  }
}

async function staged(stage, action) {
  try {
    return await action();
  } catch (error) {
    if (error instanceof ProbeError) throw error;
    throw new ProbeError(stage, error instanceof Error ? error.message : "unknown failure");
  }
}

async function run() {
  const cfg = parseProbeConfig(process.env);
  const sockets = [];
  try {
    const publicKeys = await fetchJwks(cfg.auth);
    console.log("JWKS HTTPS ingress: public Ed25519 keys verified");
    const hostToken = await issue(cfg.auth, cfg.sessions.host, cfg.room, "host");
    const clientToken = await issue(cfg.auth, cfg.sessions.client, cfg.room, "client");
    const hostClaims = await verifyTicket(hostToken, publicKeys, {
      room: cfg.room, role: "host",
    });
    const clientClaims = await verifyTicket(clientToken, publicKeys, {
      room: cfg.room, role: "client",
    });
    if (hostClaims.sub !== clientClaims.sub) {
      fail("TICKET", "Host and Client must belong to one Cloud account");
    }
    if (hostClaims.device_id === clientClaims.device_id) {
      fail("TICKET", "Host and Client must be different devices");
    }
    console.log("Real Cloud Auth issuer: valid signed Host/Client tickets verified");

    const foreignShiyan = await issueShiyan(cfg.auth, cfg.sessions.foreign);
    const foreignClaims = await verifyShiyanClaims(foreignShiyan, publicKeys);
    if (foreignClaims.sub === hostClaims.sub) {
      fail("TICKET", "foreign Session must be owned by a genuinely different account");
    }
    await issue(cfg.auth, cfg.sessions.foreign, cfg.room, "client", 403);
    await issue(cfg.auth, cfg.sessions.client, cfg.room, "host", 403);
    await issue(cfg.auth, cfg.sessions.client, otherRoom(cfg.room), "client", 403);
    console.log("Issuance authorization: foreign account, mobile-as-host, wrong room denied");

    const host = await staged("ADMISSION", async () => {
      const socket = await connect(cfg.relay, cfg.room, "host", hostToken);
      sockets.push(socket);
      await acknowledged(socket, "host", cfg.room);
      return socket;
    });
    const client = await staged("ADMISSION", async () => {
      const socket = await connect(cfg.relay, cfg.room, "client", clientToken);
      sockets.push(socket);
      await acknowledged(socket, "client", cfg.room);
      return socket;
    });
    await staged("ADMISSION", async () => {
      const crossRole = await connect(cfg.relay, cfg.room, "host", clientToken);
      sockets.push(crossRole);
      await rejected(crossRole);
    });
    await staged("ADMISSION", async () => {
      const crossRoom = await connect(cfg.relay, otherRoom(cfg.room), "client", clientToken);
      sockets.push(crossRoom);
      await rejected(crossRoom);
    });
    await staged("ADMISSION", async () => {
      const shiyan = await issueShiyan(cfg.auth, cfg.sessions.client);
      const crossAudience = await connect(cfg.relay, cfg.room, "client", shiyan);
      sockets.push(crossAudience);
      await rejected(crossAudience);
    });
    await staged("ADMISSION", async () => {
      const legacyToken = await connect(cfg.relay, cfg.room, "client", "c".repeat(48));
      sockets.push(legacyToken);
      await rejected(legacyToken);
    });
    console.log("Real Worker/DO WebSocket: Host/Client ack; room/role/audience/Legacy token denied");

    await staged("TRANSPORT", async () => {
      client.send({ type: "request", requestId: "rel005-forward", path: "/remote/v1/manifest" });
      const forwarded = await host.next();
      if (forwarded.type !== "request" || !forwarded.requestId?.endsWith("~rel005-forward")) {
        fail("TRANSPORT", "Relay request forwarding contract differed");
      }
      host.send({ type: "complete", requestId: forwarded.requestId });
      const complete = await client.next();
      if (complete.type !== "complete" || complete.requestId !== "rel005-forward") {
        fail("TRANSPORT", "Relay complete forwarding contract differed");
      }
      client.send({ type: "request", requestId: "rel005-cancel", path: "/remote/v1/manifest" });
      const pending = await host.next();
      client.send({ type: "cancel", requestId: "rel005-cancel" });
      const cancel = await host.next();
      if (pending.type !== "request" || cancel.type !== "cancel" ||
        cancel.requestId !== pending.requestId) {
        fail("TRANSPORT", "Relay cancel forwarding contract differed");
      }
    });
    console.log("Real Worker/DO transport: forward/complete/cancel verified");

    if (process.argv.includes("--expiry")) {
      const delayMs = Math.max(0, (clientClaims.exp + 1) * 1000 - Date.now());
      await sleep(delayMs);
      await staged("TRANSPORT", async () => {
        client.send({ type: "request", requestId: "rel005-after-exp", path: "/remote/v1/manifest" });
        const continued = await host.next();
        if (!continued.requestId?.endsWith("~rel005-after-exp")) {
          fail("TRANSPORT", "established socket did not survive admission-ticket expiry");
        }
        host.send({ type: "complete", requestId: continued.requestId });
        if ((await client.next()).type !== "complete") {
          fail("TRANSPORT", "post-expiry forwarding contract differed");
        }
      });
      await staged("ADMISSION", async () => {
        const expired = await connect(cfg.relay, cfg.room, "client", clientToken);
        sockets.push(expired);
        await rejected(expired);
      });
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
  console.error("REL-005 probe failed [" + failureCategory(error) + "]: " +
    redactDiagnostic(error));
  process.exitCode = 1;
});
