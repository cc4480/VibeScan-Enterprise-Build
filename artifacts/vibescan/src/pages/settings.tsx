import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSeo } from "@/lib/seo";
import { useToast } from "@/hooks/use-toast";
import { Trash2, Loader2, AlertTriangle, Mail, CreditCard, Bot } from "lucide-react";
import { AiEditorsSection } from "@/components/ai-editors";
import { ConnectedAppsSection } from "@/components/connected-apps";
import { BillingSummary } from "@/components/billing-options";
import { PrivacyCard } from "@/components/privacy-card";
import { cn } from "@/lib/utils";
import { deleteAccount, requestDeleteCode, getEmailPreferences, setEmailPreferences, type EmailPreferences, type EmailPreferenceUpdate } from "@/lib/account-api";
import { SEVERITY_CHOICES, PreferenceToggle, getFriendlyError } from "./settings-parts";

export default function SettingsPage() {
  useSeo({ title: "Settings — SecScan.us", noindex: true });
  const { toast } = useToast();

  // Typing the word is the confirmation. A dialog with a red button is too easy
  // to dismiss by reflex for something with no undo.
  const [deleteConfirm, setDeleteConfirm] = useState("");
  const [deleteChallenge, setDeleteChallenge] = useState<{ challenge: string; sentTo: string } | null>(null);
  const [deleteCode, setDeleteCode] = useState("");
  const [deleting, setDeleting] = useState(false);
  const queryClient = useQueryClient();
  const [saving, setSaving] = useState(false);

  const { data: prefs, isLoading: prefsLoading } = useQuery({
    queryKey: ["email-preferences"],
    queryFn: getEmailPreferences,
  });

  const updatePref = async (changes: EmailPreferenceUpdate) => {
    const previous = queryClient.getQueryData<EmailPreferences>(["email-preferences"]);
    queryClient.setQueryData<EmailPreferences>(["email-preferences"], (old) =>
      // `alerts` is merged rather than replaced: the optimistic update sends
      // one toggle, and spreading the parent would blank the other three
      // until the server responded.
      old ? { ...old, ...changes, alerts: { ...old.alerts, ...(changes.alerts ?? {}) } } : old,
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

  const handleSendDeleteCode = async () => {
    setDeleting(true);
    try {
      setDeleteChallenge(await requestDeleteCode());
      setDeleteCode("");
    } catch (err) {
      toast({ title: "Couldn't send the code", description: getFriendlyError(err), variant: "destructive" });
    } finally {
      setDeleting(false);
    }
  };

  const handleDeleteAccount = async () => {
    if (!deleteChallenge) return;
    setDeleting(true);
    try {
      await deleteAccount(deleteChallenge.challenge, deleteCode.trim());
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

      <div id="billing" className="glass-panel p-6 sm:p-10 rounded-3xl mb-8 scroll-mt-24">
        <div className="flex items-start gap-4 mb-6">
          <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20 shrink-0">
            <CreditCard className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h2 className="text-xl font-bold mb-1">Plan & billing</h2>
            <p className="text-sm text-muted-foreground">
              What you can scan, and how it is paid for. Payments are handled by Stripe — we never see your card.
            </p>
          </div>
        </div>
        <BillingSummary />
      </div>

      <PrivacyCard />

      <div id="ai-editors" className="glass-panel p-6 sm:p-10 rounded-3xl mb-8 scroll-mt-24">
        <div className="flex items-start gap-4 mb-6">
          <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20 shrink-0">
            <Bot className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h2 className="text-xl font-bold mb-1">AI editors and API</h2>
            <p className="text-sm text-muted-foreground">
              Scan and read reports from Claude Code, Cursor or any MCP-capable editor, or from a script or CI job through the REST API. Create a token, paste the
              setup line, then ask your editor to scan your site.
            </p>
          </div>
        </div>
        <AiEditorsSection />
        <div className="mt-8 pt-6 border-t border-white/10">
          <ConnectedAppsSection />
        </div>
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
              label="Monitor alert emails"
              description="The master switch for alert email. Your webhooks keep firing either way — turning this off quietens your inbox, not your Slack."
              checked={prefs.monitorAlerts}
              disabled={saving}
              onChange={(next) => updatePref({ monitorAlerts: next })}
            />

            <div className="mt-8 pt-6 border-t border-white/10">
              <h3 className="font-semibold mb-1">Which alerts</h3>
              <p className="text-sm text-muted-foreground mb-4">
                Applies to email and webhooks. Turn off the ones you don't act on rather
                than silencing everything.
              </p>

              <PreferenceToggle
                label="New CVEs affecting your stack"
                description="A newly published vulnerability matches a technology detected on a site you monitor, ranked by exploit probability."
                checked={prefs.alerts.cve}
                disabled={saving || !prefs.monitorAlerts}
                onChange={(next) => updatePref({ alerts: { cve: next } })}
              />
              <PreferenceToggle
                label="Regressions"
                description="Something that was fixed has come back, or a new issue appeared since the last scan."
                checked={prefs.alerts.regression}
                disabled={saving || !prefs.monitorAlerts}
                onChange={(next) => updatePref({ alerts: { regression: next } })}
              />
              <PreferenceToggle
                label="Certificate expiry"
                description="Warnings at 30, 14 and 7 days before a TLS certificate expires. These carry no severity, so the threshold below never hides them."
                checked={prefs.alerts.certExpiry}
                disabled={saving || !prefs.monitorAlerts}
                onChange={(next) => updatePref({ alerts: { certExpiry: next } })}
              />
              <PreferenceToggle
                label="Site unreachable"
                description="Your site stopped answering the hourly check, and again when it comes back. Confirmed over two consecutive checks, so a single dropped request does not alert."
                checked={prefs.alerts.availability}
                disabled={saving || !prefs.monitorAlerts}
                onChange={(next) => updatePref({ alerts: { availability: next } })}
              />
              <PreferenceToggle
                label="Configuration changed"
                description="A security header disappeared, HSTS was weakened, or the site started redirecting somewhere new — caught within the hour instead of at the next scan."
                checked={prefs.alerts.drift}
                disabled={saving || !prefs.monitorAlerts}
                onChange={(next) => updatePref({ alerts: { drift: next } })}
              />
              <PreferenceToggle
                label="Scan finished"
                description="A routine confirmation each time a scheduled rescan completes. The one most people turn off first."
                checked={prefs.alerts.scanComplete}
                disabled={saving || !prefs.monitorAlerts}
                onChange={(next) => updatePref({ alerts: { scanComplete: next } })}
              />
            </div>

            <div className="mt-8 pt-6 border-t border-white/10">
              <h3 className="font-semibold mb-1">Minimum severity</h3>
              <p className="text-sm text-muted-foreground mb-4">
                Only send CVE and regression alerts at or above this level. Certificate
                expiry is never filtered out by this.
              </p>
              <div className="flex flex-wrap gap-2">
                {SEVERITY_CHOICES.map((choice) => (
                  <button
                    key={choice.value}
                    type="button"
                    disabled={saving}
                    onClick={() => updatePref({ minSeverity: choice.value })}
                    className={cn(
                      "px-3.5 py-2 rounded-xl text-sm font-medium border transition-colors disabled:opacity-50",
                      prefs.minSeverity === choice.value
                        ? "bg-primary text-primary-foreground border-primary"
                        : "bg-secondary text-muted-foreground border-white/10 hover:text-foreground",
                    )}
                  >
                    {choice.label}
                  </button>
                ))}
              </div>
            </div>
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
          {!deleteChallenge && (
            <button
              type="button"
              onClick={handleSendDeleteCode}
              disabled={deleteConfirm !== "DELETE" || deleting}
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-red-500/90 text-white font-bold text-sm disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              {deleting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
              Email me a code
            </button>
          )}
        </div>
        {deleteChallenge && (
          <div className="mt-4">
            <label className="block text-sm text-muted-foreground mb-2">
              We sent a 6-digit code to {deleteChallenge.sentTo}. Enter it to erase the account.
            </label>
            <div className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={deleteCode}
                onChange={(e) => setDeleteCode(e.target.value)}
                aria-label="6-digit code"
                className="flex-1 px-4 py-3 rounded-xl bg-black/30 border border-white/10 text-sm font-mono focus:outline-none focus:border-red-500/50"
              />
              <button
                type="button"
                onClick={handleDeleteAccount}
                disabled={deleteConfirm !== "DELETE" || deleteCode.trim().length < 6 || deleting}
                className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-red-500/90 text-white font-bold text-sm disabled:opacity-40 disabled:cursor-not-allowed transition-all"
              >
                {deleting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                Delete my account
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}