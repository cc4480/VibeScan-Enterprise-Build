/**
 * Health and status endpoints that tell strangers about the server.
 *
 * A public health check is normal and correct: load balancers and uptime
 * monitors need one. What is worth reporting is a health check that answers
 * anyone with runtime internals: process uptime (which dates the last deploy),
 * memory use, host or instance names, a Node/Python version. That is
 * fingerprinting an attacker gets for free.
 *
 * Reported INFO, never higher: none of this is a weakness on its own, and
 * calling it a privacy violation (as one rival does) is exactly the overstatement
 * this scanner avoids.
 *
 * False-positive rules, each with a clean twin in the vuln fixture:
 * - JSON only. An HTML 200 is a SPA catch-all or a status page, not an API.
 * - A bare {"status":"ok"} (or ok/healthy/up plus timestamps) is silent: the
 *   finding needs at least one RUNTIME field from the list below.
 * - "version" alone does not count: "public beta" or a git sha is product
 *   information, not software an attacker can look up. A runtime version does
 *   ("node": "v20.1.0", "python": "3.11").
 * - Responses behind authentication (401/403) are never read.
 *
 * Read-only GETs, a handful of paths, first hit wins.
 */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanFetch } from "./http";

const TIMEOUT_MS = 6_000;

export const HEALTH_PATHS = [
  "/api/health",
  "/api/healthz",
  "/api/system/health",
  "/api/status",
  "/health",
  "/healthz",
  "/status",
  "/actuator/health",
];

/**
 * Keys that reveal runtime internals. Deliberately narrow: "host", "platform",
 * "os", "load" and a bare "node" mean too many harmless things to count.
 */
const RUNTIME_KEYS = new Set([
  "uptime", "uptimeseconds", "uptime_seconds", "uptimems",
  "memory", "heapused", "heaptotal", "rss", "rssmb", "memoryusage",
  "hostname", "instance", "instanceid", "instance_id", "pod", "podname", "container", "containerid",
  "pid", "nodeversion", "node_version", "pythonversion", "python_version", "runtimeversion",
]);

/** A value that only reports a check passed ({"memory":"ok"}) discloses nothing. */
const STATUS_WORDS = /^(ok|okay|up|healthy|pass|passed|green|online|true|good|ready|alive)$/i;
const disclosing = (v: unknown) =>
  typeof v === "number" || (typeof v === "object" && v !== null) || (typeof v === "string" && v.trim() !== "" && !STATUS_WORDS.test(v.trim()));

function runtimeKeys(value: unknown, out: Set<string>, depth = 0): Set<string> {
  if (depth > 4 || value === null || typeof value !== "object") return out;
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    const key = k.toLowerCase();
    if (RUNTIME_KEYS.has(key) && disclosing(v)) out.add(k);
    runtimeKeys(v, out, depth + 1);
  }
  return out;
}

/** The runtime fields a health response exposes. Empty means nothing worth reporting. Exported for tests. */
export function runtimeKeysIn(body: string, contentType: string): string[] {
  if (!contentType.toLowerCase().includes("json")) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return [];
  }
  return [...runtimeKeys(parsed, new Set())];
}

export async function runHealthEndpointProbe(targetUrl: string): Promise<ScanVulnerability[]> {
  let origin: string;
  try {
    origin = new URL(targetUrl).origin;
  } catch {
    return [];
  }

  for (const path of HEALTH_PATHS) {
    const res = await scanFetch(`${origin}${path}`, { timeoutMs: TIMEOUT_MS });
    if (!res || res.status !== 200) continue;
    const exposed = runtimeKeysIn(res.body, res.headers["content-type"] ?? "");
    if (exposed.length === 0) continue;

    return [{
      id: randomUUID(),
      name: "Health Endpoint Discloses Runtime Details",
      severity: "info",
      category: "Information Disclosure",
      description:
        `${path} answers without a login and includes runtime details (${exposed.join(", ")}). ` +
        "A public health check is normal; these fields are not needed by a load balancer and tell an attacker " +
        "when you last deployed and what the server is running. This is not a vulnerability on its own.",
      evidence: `GET ${origin}${path} → 200\nFields exposed: ${exposed.join(", ")}\n${res.body.slice(0, 300)}`,
      solution:
        `Keep ${path} public but return only a status, e.g. {"status":"ok"}. Move uptime, memory, instance and ` +
        "version details to an endpoint that requires authentication.",
      cweId: "CWE-200",
      wstgId: "WSTG-INFO-02",
      confidence: 95,
    }];
  }
  return [];
}
