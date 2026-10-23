import { useState } from "react";
import type { QuietHours } from "@/lib/account-api";

const HOURS = Array.from({ length: 24 }, (_, h) => h);
const hourLabel = (h: number) => `${String(h).padStart(2, "0")}:00`;

/** The zone the browser is in, which is what most people mean; "UTC" if it cannot say. */
function browserZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

/** The zones to offer: the browser's own first, then every zone the browser knows. */
function zoneChoices(current: string): string[] {
  let all: string[] = [];
  try {
    all = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.("timeZone") ?? [];
  } catch {
    all = [];
  }
  return Array.from(new Set([current, browserZone(), "UTC", ...all]));
}

/**
 * A daily window when alerts are not sent. What still gets through is stated here, in the
 * same words the server enforces (notificationPrefs.ts): a critical finding, an expiring
 * certificate and an outage. Everything held is still in the dashboard.
 */
export function QuietHoursSection({ value, saving, onChange }: {
  value: QuietHours | null;
  saving: boolean;
  onChange: (next: QuietHours | null) => void;
}) {
  const [draft, setDraft] = useState<QuietHours>(value ?? { start: 22, end: 7, timezone: browserZone() });
  const window = value ?? draft;
  const same = window.start === window.end;

  function edit(part: Partial<QuietHours>) {
    const next = { ...window, ...part };
    setDraft(next);
    // A window with the same start and end is nothing; wait for a real one before saving.
    if (value && next.start !== next.end) onChange(next);
  }

  return (
    <div className="mt-8 pt-6 border-t border-white/10">
      <div className="flex items-start justify-between gap-4 mb-1">
        <h3 className="font-semibold">Quiet hours</h3>
        <button
          type="button"
          role="switch"
          aria-checked={Boolean(value)}
          aria-label="Quiet hours"
          disabled={saving}
          onClick={() => onChange(value ? null : draft.start === draft.end ? { ...draft, end: (draft.start + 8) % 24 } : draft)}
          className={`w-11 h-6 rounded-full border transition-colors disabled:opacity-50 shrink-0 ${value ? "bg-primary border-primary" : "bg-secondary border-white/10"}`}
        >
          <span className={`block w-4 h-4 rounded-full bg-white transition-transform mx-1 ${value ? "translate-x-5" : ""}`} />
        </button>
      </div>
      <p className="text-sm text-muted-foreground mb-4">
        Between these hours we hold back emails and webhooks, except a critical finding, a certificate about to expire, or your site going down or coming back.
        What we hold back is still in your dashboard.
      </p>
      {value && (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <label className="flex items-center gap-2">From
            <select aria-label="Quiet hours start" disabled={saving} value={window.start} onChange={(e) => edit({ start: Number(e.target.value) })} className="px-2 py-1.5 rounded-lg bg-secondary border border-white/10">
              {HOURS.map((h) => <option key={h} value={h}>{hourLabel(h)}</option>)}
            </select>
          </label>
          <label className="flex items-center gap-2">to
            <select aria-label="Quiet hours end" disabled={saving} value={window.end} onChange={(e) => edit({ end: Number(e.target.value) })} className="px-2 py-1.5 rounded-lg bg-secondary border border-white/10">
              {HOURS.map((h) => <option key={h} value={h}>{hourLabel(h)}</option>)}
            </select>
          </label>
          <label className="flex items-center gap-2">in
            <select aria-label="Quiet hours time zone" disabled={saving} value={window.timezone} onChange={(e) => edit({ timezone: e.target.value })} className="px-2 py-1.5 rounded-lg bg-secondary border border-white/10 max-w-[14rem]">
              {zoneChoices(window.timezone).map((z) => <option key={z} value={z}>{z}</option>)}
            </select>
          </label>
        </div>
      )}
      {value && same && <p role="alert" className="text-xs text-amber-400 mt-2">Pick two different hours.</p>}
    </div>
  );
}
