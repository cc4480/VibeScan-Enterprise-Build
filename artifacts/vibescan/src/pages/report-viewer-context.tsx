import { createContext, useContext } from "react";
import type { Vulnerability } from "@workspace/api-client-react";


export interface DismissalEntry {
  fingerprint: string;
  findingName: string;
  findingCategory: string;
}

// ─── Client-side fingerprint helpers (mirror server lib/fingerprint.ts) ────────

export function normalizeEvidenceKeyClient(evidence?: string | null): string {
  if (!evidence) return "";
  return evidence
    .toLowerCase()
    .replace(/https?:\/\/[^\s]+/g, "url")
    .replace(/\b[0-9a-f]{8,}\b/gi, "hash")
    .replace(/\b\d[\d.]+\d\b/g, "N")
    .replace(/['"`;,]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 50);
}

export async function computeVulnFp(
  category: string,
  name: string,
  evidence?: string | null,
): Promise<string> {
  const evidenceKey = normalizeEvidenceKeyClient(evidence);
  const input = evidenceKey
    ? `${category.toLowerCase().trim()}::${name.toLowerCase().trim()}::${evidenceKey}`
    : `${category.toLowerCase().trim()}::${name.toLowerCase().trim()}`;
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 20);
}

export function vulnUniqueKey(v: { category: string; name: string; evidence?: string | null }): string {
  return `${v.category}:${v.name}:${v.evidence ?? ""}`;
}

// ─── Dismissals context ──────────────────────────────────────────────────────

export interface DismissalsCtx {
  dismissedFps: Set<string>;
  vulnFpMap: Map<string, string>;
  optimisticDismissKeys: Set<string>;
  dismiss: (vuln: Vulnerability, targetUrl: string) => Promise<void>;
  undismiss: (vuln: Vulnerability) => Promise<void>;
}

export const DismissalsContext = createContext<DismissalsCtx>({
  dismissedFps: new Set(),
  vulnFpMap: new Map(),
  optimisticDismissKeys: new Set(),
  dismiss: async () => {},
  undismiss: async () => {},
});
