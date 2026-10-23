/** The add-a-site form. */
import { useState } from "react";
import { Link } from "wouter";
import { motion, AnimatePresence } from "framer-motion";
import { Bell, Plus, ChevronDown, ChevronUp, Loader2, Webhook } from "lucide-react";
import { createMonitorSubscription } from "@/lib/monitor-api";
import { useToast } from "@/hooks/use-toast";
import { ApiError } from "@workspace/api-client-react";
import { BuyOptions } from "@/components/billing-options";

// ── Add subscription form ─────────────────────────────────────────────────────

export function AddSubscriptionForm({ onSuccess }: { onSuccess: () => void }) {
  const [url, setUrl] = useState("https://");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [showWebhook, setShowWebhook] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Set when the server says monitoring needs a plan (only once
  // MONITORING_REQUIRES_PLAN is on). The moment someone asks to monitor is the
  // moment to offer the plan — a bare error there loses the sale.
  const [refusal, setRefusal] = useState<"plan" | "limit" | null>(null);
  const { toast } = useToast();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setRefusal(null);
    setLoading(true);
    try {
      const result = await createMonitorSubscription(
        url.trim(),
        webhookUrl.trim() || undefined,
      );
      // An earlier scan of the same site is found and shown on the card; say so, with its date and grade.
      const earlier = result.seededFrom
        ? ` Found your earlier scan of this site (${new Date(result.seededFrom.scannedAt).toLocaleDateString()}${result.seededFrom.grade ? `, grade ${result.seededFrom.grade}` : ""}) and kept it as the starting point.`
        : "";
      if (result.initialScanId) {
        toast({ title: "Monitoring activated", description: `Baseline scan queued for ${url.trim()} — results will appear shortly.${earlier}` });
      } else {
        toast({ title: "Monitoring activated", description: "Using your most recent scan results. The next full scan is scheduled from your security grade." });
      }
      onSuccess();
    } catch (err: unknown) {
      // Keyed on the server's code, never on the prose, which will be reworded.
      const data = err instanceof ApiError ? (err.data as { code?: unknown; reason?: unknown } | null) : null;
      const code = data?.code;
      if (code === "monitor_plan_required") setRefusal("plan");
      // A free account at its one site is shown the plans; a paid one is pointed at its own limit.
      else if (code === "monitor_url_limit") setRefusal(data?.reason === "free" ? "plan" : "limit");
      const msg = err instanceof Error ? err.message : "Failed to create subscription";
      setError(msg.replace(/^HTTP \d+ [^:]+: /, ""));
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="glass-card rounded-2xl p-6">
      <h3 className="font-bold mb-4 flex items-center gap-2">
        <Plus className="w-4 h-4 text-primary" /> Monitor a new URL
      </h3>
      <div className="flex flex-col sm:flex-row gap-3 mb-3">
        <input
          id="monitor-url"
          type="url"
          value={url}
          // The field starts as "https://", so pasting a full address — the
          // normal way to enter one on a phone — produced "https://https://…".
          // Collapse a doubled scheme to the one that was pasted.
          onChange={(e) => setUrl(e.target.value.replace(/^(?:https?:\/\/)+(https?:\/\/)/i, "$1"))}
          placeholder="https://yourapp.com"
          required
          className="flex-1 bg-background/60 border border-white/10 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-primary/50 transition-colors"
        />
        <button
          type="submit"
          disabled={loading}
          className="px-5 py-2.5 bg-primary text-primary-foreground font-semibold rounded-xl hover:shadow-[0_0_20px_rgba(20,184,120,0.4)] transition-all disabled:opacity-60 flex items-center justify-center gap-2"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Bell className="w-4 h-4" />}
          {loading ? "Starting…" : "Start Monitoring"}
        </button>
      </div>

      <button
        type="button"
        onClick={() => setShowWebhook((x) => !x)}
        className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors mb-2"
      >
        <Webhook className="w-3.5 h-3.5" />
        {showWebhook ? "Hide" : "Add"} webhook (optional — Slack / Discord / Teams)
        {showWebhook ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
      </button>

      <AnimatePresence>
        {showWebhook && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <input
              id="monitor-webhook"
              type="url"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
              className="w-full bg-background/60 border border-white/10 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-primary/50 transition-colors mb-2"
            />
            <p className="text-xs text-muted-foreground mb-3">
              Receives Slack-compatible JSON for CVE matches, regressions, certificate expiry, outages, configuration changes and completed scans.
            </p>
          </motion.div>
        )}
      </AnimatePresence>

      {error && <p className="mt-2 text-sm text-red-400">{error}</p>}
      {refusal === "plan" && (
        <div className="mt-5">
          <BuyOptions compact />
        </div>
      )}
      {refusal === "limit" && (
        <p className="mt-2 text-sm text-muted-foreground">
          You've reached your plan's site limit. Stop monitoring one below to add another, or{" "}
          <Link href="/settings#billing" className="text-primary underline underline-offset-2">see your plan</Link>.
        </p>
      )}
    </form>
  );
}
