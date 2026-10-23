/** Shared finding constructor and bounded fetch for the Supabase probes. */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { readBodyBounded } from "./httpBody";

export const TIMEOUT_MS = 10_000;

export const MAX_TABLES_TO_TEST = 12;

export function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

export interface FetchResult {
  status: number;
  body: string;
  headers: Record<string, string>;
}

export async function safeFetch(
  url: string,
  options: RequestInit = {},
  timeoutMs = TIMEOUT_MS,
): Promise<FetchResult | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    const body = await readBodyBounded(res);
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { status: res.status, body, headers };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
