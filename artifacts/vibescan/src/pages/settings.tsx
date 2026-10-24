import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSeo } from "@/lib/seo";
import { useToast } from "@/hooks/use-toast";
import { Loader2, Mail, CreditCard, Bot, Github, Palette, ShieldCheck, Ticket } from "lucide-react";
import { AiEditorsSection } from "@/components/ai-editors";
import { GithubIssuesSection } from "@/components/github-issues-section";
import { TicketsSection } from "@/components/tickets-section";
import { BrandingSection } from "@/components/branding-section";
import { TrustPagesSection } from "@/components/trust-pages-section";
import { QuietHoursSection } from "@/components/quiet-hours-section";
import { ConnectedAppsSection } from "@/components/connected-apps";
import { BillingSummary } from "@/components/billing-summary";
import { PrivacyCard } from "@/components/privacy-card";
import { cn } from "@/lib/utils";
import { getEmailPreferences, setEmailPreferences, type EmailPreferences, type EmailPreferenceUpdate } from "@/lib/account-api";
import { SEVERITY_CHOICES, PreferenceToggle, getFriendlyError } from "./settings-parts";
import { DeleteAccountSection } from "./settings-delete-account";

export default function SettingsPage() {
  useSeo({ title: "Settings — SecScan.us", noindex: true });
  const { toast } = useToast();

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
        <div className="flex items-start gap-4 mb-6">
          <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20 shrink-0">
            <Github className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h2 className="text-xl font-bold mb-1">GitHub issues</h2>
            <p className="text-sm text-muted-foreground">
              Turn a finding into a GitHub issue from the report, with the evidence, the fix and a link back. Each problem on a site is filed once.
            </p>
          </div>
        </div>
        <GithubIssuesSection />
      </div>

      <div className="glass-panel p-6 sm:p-10 rounded-3xl mb-8">
        <div className="flex items-start gap-4 mb-6">
          <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20 shrink-0">
            <Ticket className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h2 className="text-xl font-bold mb-1">Linear and Jira</h2>
            <p className="text-sm text-muted-foreground">
              Turn a finding into a Linear issue or a Jira ticket from the report, with the evidence, the fix and a link back. Each problem on a site is filed once per place.
            </p>
          </div>
        </div>
        <TicketsSection />
      </div>

      <div className="glass-panel p-6 sm:p-10 rounded-3xl mb-8">
        <div className="flex items-start gap-4 mb-6">
          <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20 shrink-0">
            <Palette className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h2 className="text-xl font-bold mb-1">Report branding</h2>
            <p className="text-sm text-muted-foreground">
              Put your own name on the PDFs and shared reports you send to clients, in place of SecScan's.
            </p>
          </div>
        </div>
        <BrandingSection />
      </div>

      <div className="glass-panel p-6 sm:p-10 rounded-3xl mb-8">
        <div className="flex items-start gap-4 mb-6">
          <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20 shrink-0">
            <ShieldCheck className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h2 className="text-xl font-bold mb-1">Trust pages</h2>
            <p className="text-sm text-muted-foreground">
              Show customers the grade and date of your latest scan on a public page under your name and colour. Only for domains you have verified; it never lists the findings.
            </p>
          </div>
        </div>
        <TrustPagesSection />
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

            <QuietHoursSection value={prefs.quietHours} saving={saving} onChange={(quietHours) => updatePref({ quietHours })} />
          </div>
        ) : null}
      </div>

      <DeleteAccountSection />
    </div>
  );
}