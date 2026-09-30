/** Formatting, cadence and grade helpers for the monitor page. */
export const SEVERITY_CONFIG: Record<string, { label: string; color: string; bg: string }> = {
  CRITICAL: { label: "Critical", color: "text-red-400",    bg: "bg-red-400/10 border-red-400/20" },
  HIGH:     { label: "High",     color: "text-orange-400", bg: "bg-orange-400/10 border-orange-400/20" },
  MEDIUM:   { label: "Medium",   color: "text-yellow-400", bg: "bg-yellow-400/10 border-yellow-400/20" },
  LOW:      { label: "Low",      color: "text-green-400",  bg: "bg-green-400/10 border-green-400/20" },
  UNKNOWN:  { label: "Unknown",  color: "text-zinc-400",   bg: "bg-zinc-400/10 border-zinc-400/20" },
};

export function gradeColor(grade: string | null) {
  if (!grade) return "text-muted-foreground";
  if (grade === "A" || grade === "B") return "text-green-400";
  if (grade === "C") return "text-yellow-400";
  if (grade === "D") return "text-orange-400";
  return "text-red-400";
}

/** Published cadence, so the card can explain the date it is showing. */
export function cadenceDays(grade: string | null): number | null {
  if (!grade) return null;
  if (grade === "A") return 14;
  if (grade === "B" || grade === "C") return 7;
  if (grade === "D" || grade === "F") return 3;
  return null;
}

export function daysRemaining(expiresAt: string): number {
  return Math.max(0, Math.ceil((new Date(expiresAt).getTime() - Date.now()) / 86_400_000));
}

export function formatDate(iso: string | null): string {
  if (!iso) return "Never";
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

/**
 * "12 min ago" rather than a timestamp.
 *
 * The whole point of the hourly check is that somebody can see at a glance that
 * the product looked recently. A formatted date makes that a subtraction the
 * reader has to do.
 */
export function relativeTime(iso: string | null): string {
  if (!iso) return "not yet";
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 0) return "just now";
  if (seconds < 90) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hour${hours !== 1 ? "s" : ""} ago`;
  const days = Math.round(hours / 24);
  return `${days} day${days !== 1 ? "s" : ""} ago`;
}

/** Time until a future moment, or "due now" once it has passed. */
export function untilLabel(iso: string | null): string {
  if (!iso) return "—";
  const ms = new Date(iso).getTime() - Date.now();
  if (ms <= 0) return "due now";
  const hours = Math.round(ms / 3_600_000);
  if (hours < 24) return `in ${hours} hour${hours !== 1 ? "s" : ""}`;
  const days = Math.round(hours / 24);
  return `in ${days} day${days !== 1 ? "s" : ""}`;
}

export function formatMs(ms: number | null): string {
  if (ms == null) return "—";
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

// ── Score trend chart ─────────────────────────────────────────────────────────

// Letter grade to a 0–100 scale for charting. Higher is better.
export const GRADE_NUMERIC: Record<string, number> = { A: 100, B: 80, C: 60, D: 40, F: 20 };

// ── Portfolio summary ─────────────────────────────────────────────────────────

export const GRADE_ORDER = ["F", "D", "C", "B", "A"];

export function hostOf(url: string): string {
  try { return new URL(url).host; } catch { return url; }
}
