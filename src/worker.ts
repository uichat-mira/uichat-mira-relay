import { PROTOCOL_VERSION, RELAY_ID_PATTERN, parseRelayId, isWebSocketUpgrade } from "./protocol.js";
export type Env = { RELAY_ROOMS: DurableObjectNamespace };
export const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return json({
        ok: true,
        service: "mira-remote-relay",
        protocolVersion: PROTOCOL_VERSION,
      });
    }

    const relayId = parseRelayId(url.pathname);
    if (!relayId || !RELAY_ID_PATTERN.test(relayId)) {
      return json({ error: "not_found" }, 404);
    }
    if (!isWebSocketUpgrade(request)) {
      return json({ error: "websocket_required" }, 426);
    }

    const id = env.RELAY_ROOMS.idFromName(relayId);
    return env.RELAY_ROOMS.get(id).fetch(request);
  },
};
