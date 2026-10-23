/** Shared helpers for the BaaS probes. */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanFetch } from "./http";

export const TIMEOUT_MS = 8_000;

export function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

export async function safeGet(
  url: string,
  headers?: Record<string, string>,
): Promise<{ status: number; body: string } | null> {
  // scanFetch checks the address of every hop, which a bare fetch with redirect: "follow" does not.
  const res = await scanFetch(url, { timeoutMs: TIMEOUT_MS, headers });
  return res ? { status: res.status, body: res.body } : null;
}

export function extractInlineJs(html: string): string {
  const rx = /<script(?:[^>]*)>([\s\S]*?)<\/script>/gi;
  const parts: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = rx.exec(html)) !== null) {
    if (!/\bsrc\s*=/i.test(m[0])) parts.push(m[1] ?? "");
  }
  return parts.join("\n");
}
