/** Preference toggle and helpers for the settings page. */
import { type AlertSeverity } from "@/lib/account-api";

/**
 * Ordered least to most urgent, so the row reads as a threshold rather than a
 * set of options. "Everything" rather than "Info" because that is what
 * choosing it does — the stored value is still "info".
 */
export const SEVERITY_CHOICES: { value: AlertSeverity; label: string }[] = [
  { value: "info", label: "Everything" },
  { value: "low", label: "Low and up" },
  { value: "medium", label: "Medium and up" },
  { value: "high", label: "High and up" },
  { value: "critical", label: "Critical only" },
];

/** Row with a switch. Optimistic: the toggle moves on click and reverts if the
 *  save fails, because a control that lags a round trip feels broken. */
export function PreferenceToggle({
  label,
  description,
  checked,
  disabled,
  onChange,
}: {
  label: string;
  description: string;
  checked: boolean;
  disabled: boolean;
  onChange: (next: boolean) => void;
}) {
  return (
    <div className="flex items-start justify-between gap-6 py-4 border-b border-white/5 last:border-0">
      <div className="min-w-0">
        <div className="font-medium text-sm mb-1">{label}</div>
        <p className="text-sm text-muted-foreground leading-relaxed">{description}</p>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`shrink-0 mt-1 w-11 h-6 rounded-full transition-colors disabled:opacity-50 ${
          checked ? "bg-primary" : "bg-white/15"
        }`}
      >
        <span
          className={`block w-5 h-5 rounded-full bg-white transition-transform ${
            checked ? "translate-x-[22px]" : "translate-x-[2px]"
          }`}
        />
      </button>
    </div>
  );
}

export function getFriendlyError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err ?? "");
  if (!msg) return "Something went wrong. Please try again.";
  if (/unauthorized|401/i.test(msg)) return "Session expired. Please sign in again.";
  const clean = msg.replace(/^HTTP \d{3} [^:]+:\s*/, "");
  return clean.length > 160 ? clean.slice(0, 160) + "…" : clean;
}
