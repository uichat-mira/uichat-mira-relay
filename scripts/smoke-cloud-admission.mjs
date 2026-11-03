const fail = (reason) => {
  console.error("CLOUD_RELAY_SMOKE: FAIL (" + reason + ")");
  process.exitCode = 1;
};

const rawOrigin = process.env.CLOUD_RELAY_ORIGIN;
let origin;
try {
  origin = new URL(rawOrigin);
} catch {
  fail("INVALID_ORIGIN");
}

if (process.exitCode !== 1) {
  if (
    origin.protocol !== "https:" ||
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash
  ) {
    fail("UNSAFE_ORIGIN");
  }
}

if (process.exitCode !== 1 && typeof WebSocket !== "function") {
  fail("WEBSOCKET_RUNTIME_UNAVAILABLE");
}

if (process.exitCode !== 1) {
  const room = "cloud-relay-smoke-room-00000001";
  const socketUrl = new URL(
    "/v1/relay/" + room + "/socket",
    origin,
  );
  socketUrl.protocol = "wss:";

  const socket = new WebSocket(socketUrl);
  let denialSeen = false;
  let settled = false;
  let timer;
  const finish = (ok, reason) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    if (ok) {
      console.log("CLOUD_RELAY_SMOKE: PASS (no-ticket denied with close code 1008)");
      return;
    }
    fail(reason);
    try {
      socket.close();
    } catch {
      // Preserve the bounded smoke failure.
    }
  };
  timer = setTimeout(() => finish(false, "TIMEOUT"), 10_000);

  socket.addEventListener("open", () => {
    socket.send(JSON.stringify({
      version: 1,
      type: "hello",
      role: "client",
      relayId: room,
    }));
  });

  socket.addEventListener("message", event => {
    let frame;
    try {
      frame = JSON.parse(String(event.data));
    } catch {
      finish(false, "INVALID_ERROR_FRAME");
      return;
    }
    if (frame?.type !== "error" || frame?.code !== "CLOUD_TICKET_REQUIRED") {
      finish(false, "UNEXPECTED_ADMISSION_RESULT");
      return;
    }
    denialSeen = true;
  });

  socket.addEventListener("close", event => {
    finish(denialSeen && event.code === 1008, "CLOUD_ADMISSION_NOT_FAIL_CLOSED");
  });

  socket.addEventListener("error", () => {
    finish(false, "WEBSOCKET_ERROR");
  });
}