/** Shared helpers for the BaaS probes. */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

export const TIMEOUT_MS = 8_000;

export function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

export async function safeGet(
  url: string,
  headers?: Record<string, string>,
): Promise<{ status: number; body: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": "Mozilla/5.0 SecScan Security Scanner", ...headers },
      signal: controller.signal,
      redirect: "follow",
    });
    const body = await res.text().catch(() => "");
    return { status: res.status, body };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
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
