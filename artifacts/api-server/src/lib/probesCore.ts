/** Shared helpers for the HTTP probes. */
import { randomUUID } from "node:crypto";
import { scanFetch, type HttpResult } from "./http";
import type { ScanVulnerability } from "./scanner";

export const PROBE_TIMEOUT_MS = 8_000;

export function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

/**
 * Thin alias over the shared scan client, kept so the 13 probes below read
 * unchanged. Timeout default, no-cache headers and the null-on-failure contract
 * all now come from lib/http.ts.
 */
export async function safeGet(
  url: string,
  options: RequestInit = {},
  timeoutMs = PROBE_TIMEOUT_MS,
): Promise<HttpResult | null> {
  return scanFetch(url, { ...options, timeoutMs });
}
