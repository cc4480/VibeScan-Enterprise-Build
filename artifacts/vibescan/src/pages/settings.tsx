import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSeo } from "@/lib/seo";
import { useToast } from "@/hooks/use-toast";
import { Trash2, Loader2, AlertTriangle, Mail } from "lucide-react";
import {
  deleteAccount,
  getEmailPreferences,
  setEmailPreferences,
  type EmailPreferences,
} from "@/lib/account-api";

/** Row with a switch. Optimistic: the toggle moves on click and reverts if the
 *  save fails, because a control that lags a round trip feels broken. */
function PreferenceToggle({
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

function getFriendlyError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err ?? "");
  if (!msg) return "Something went wrong. Please try again.";
  if (/unauthorized|401/i.test(msg)) return "Session expired. Please sign in again.";
  const clean = msg.replace(/^HTTP \d{3} [^:]+:\s*/, "");
  return clean.length > 160 ? clean.slice(0, 160) + "…" : clean;
}

export default function SettingsPage() {
  useSeo({ title: "Settings — SecScan", noindex: true });
  const { toast } = useToast();

  // Typing the word is the confirmation. A dialog with a red button is too easy
  // to dismiss by reflex for something with no undo.
  const [deleteConfirm, setDeleteConfirm] = useState("");
  const [deleting, setDeleting] = useState(false);
  const queryClient = useQueryClient();
  const [saving, setSaving] = useState(false);

  const { data: prefs, isLoading: prefsLoading } = useQuery({
    queryKey: ["email-preferences"],
    queryFn: getEmailPreferences,
  });

  const updatePref = async (changes: Partial<EmailPreferences>) => {
    const previous = queryClient.getQueryData<EmailPreferences>(["email-preferences"]);
    queryClient.setQueryData<EmailPreferences>(["email-preferences"], (old) =>
      old ? { ...old, ...changes } : old,
    );
    setSaving(true);
    try {
      const saved = await setEmailPreferences(changes);
      queryClient.setQueryData(["email-preferences"], saved);
    } catch (err) {
      // Put the switch back where it was; leaving it flipped would claim a
      // preference we did not manage to store.
      if (previous) queryClient.setQueryData(["email-preferences"], previous);
      toast({
        title: "Couldn't save preference",
        description: getFriendlyError(err),
        variant: "destructive",
      });
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteAccount = async () => {
    setDeleting(true);
    try {
      await deleteAccount();
      // Full reload rather than a router push: every cached query belongs to an
      // account that no longer exists.
      window.location.href = "/";
    } catch (err) {
      setDeleting(false);
      toast({
        title: "Couldn't delete account",
        description: getFriendlyError(err),
        variant: "destructive",
      });
    }
  };

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="mb-10">
        <h1 className="text-3xl md:text-4xl font-bold tracking-tight mb-3">Settings</h1>
        <p className="text-muted-foreground text-lg">Manage your account.</p>
      </div>

      <div className="glass-panel p-6 sm:p-10 rounded-3xl mb-8">
        <div className="flex items-start gap-4 mb-2">
          <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20 shrink-0">
            <Mail className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h2 className="text-xl font-bold mb-1">Email</h2>
            <p className="text-sm text-muted-foreground">
              Account emails — password resets, email verification and purchase receipts —
              always send, and are not listed here.
            </p>
          </div>
        </div>

        {prefsLoading ? (
          <div className="flex items-center gap-2 text-muted-foreground text-sm py-4">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading preferences…
          </div>
        ) : prefs ? (
          <div className="mt-4">
            <PreferenceToggle
              label="Product updates"
              description="New features, security research and the occasional announcement. Not more than we would want to receive ourselves."
              checked={prefs.productUpdates}
              disabled={saving}
              onChange={(next) => updatePref({ productUpdates: next })}
            />
            <PreferenceToggle
              label="Monitor alerts"
              description="CVE matches, security regressions and certificate expiry warnings for the targets you monitor. Turning these off means we will not tell you when something breaks."
              checked={prefs.monitorAlerts}
              disabled={saving}
              onChange={(next) => updatePref({ monitorAlerts: next })}
            />
          </div>
        ) : null}
      </div>

      <div className="glass-panel p-6 sm:p-10 rounded-3xl border border-red-500/20">
        <div className="flex items-start gap-4 mb-6">
          <div className="w-12 h-12 rounded-2xl bg-red-500/10 flex items-center justify-center border border-red-500/20 shrink-0">
            <AlertTriangle className="w-6 h-6 text-red-400" />
          </div>
          <div>
            <h2 className="text-xl font-bold mb-1">Delete account</h2>
            <p className="text-sm text-muted-foreground leading-relaxed">
              Permanently erases your account, every scan and report, your saved credentials,
              your credits and your verified domains. Share links stop working. This cannot be
              undone and there is no grace period. Payment records are kept by Stripe where
              accounting law requires it.
            </p>
          </div>
        </div>

        <label className="block text-sm text-muted-foreground mb-2">
          Type <span className="font-mono text-foreground">DELETE</span> to confirm
        </label>
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={deleteConfirm}
            onChange={(e) => setDeleteConfirm(e.target.value)}
            aria-label="Type DELETE to confirm"
            className="flex-1 px-4 py-3 rounded-xl bg-black/30 border border-white/10 text-sm font-mono focus:outline-none focus:border-red-500/50"
          />
          <button
            type="button"
            onClick={handleDeleteAccount}
            disabled={deleteConfirm !== "DELETE" || deleting}
            className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-red-500/90 text-white font-bold text-sm disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {deleting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
            Delete my account
          </button>
        </div>
      </div>
    </div>
  );
}
