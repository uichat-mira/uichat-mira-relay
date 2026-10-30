/** Deployment-wide transport admission mode. Never infer mode from a JWT. */
export type RelayAdmissionMode = "legacy" | "cloud";

export type RelayAdmissionSettings = {
  RELAY_ADMISSION_MODE?: string;
  CLOUD_AUTH_JWKS_URL?: string;
};

/** Undefined means the already-deployed Legacy V1 path, not Cloud fallback.
 * Partially configured or mistyped Cloud settings fail closed.
 */
export function resolveAdmissionMode(env: RelayAdmissionSettings): RelayAdmissionMode | null {
  const mode = env.RELAY_ADMISSION_MODE;
  const jwks = env.CLOUD_AUTH_JWKS_URL;

  if (mode === undefined && jwks === undefined) return "legacy";
  if (mode === "legacy" && jwks === undefined) return "legacy";
  if (mode !== "cloud" || typeof jwks !== "string") return null;

  try {
    const url = new URL(jwks);
    if (
      url.protocol !== "https:" ||
      url.username !== "" ||
      url.password !== "" ||
      url.search !== "" ||
      url.hash !== "" ||
      url.pathname !== "/.well-known/jwks.json"
    ) return null;
    return "cloud";
  } catch {
    return null;
  }
}

/** Cloud rooms and their sockets/SQLite must never share a Legacy DO instance. */
export function durableRoomKey(room: string, mode: RelayAdmissionMode): string {
  return mode === "cloud" ? `cloud:${room}` : room;
}
