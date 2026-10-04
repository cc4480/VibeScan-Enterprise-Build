import { useState, type ReactNode } from "react";
import { Link } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { useGetCurrentAuthUser } from "@workspace/api-client-react";
import { Bell, CheckCircle2, Loader2, Package } from "lucide-react";
import { cn } from "@/lib/utils";
import { buyPack, formatUsd, getBillingCatalog, getBillingStatus, perScanCents, planPerScanLabel, planScansLine, subscribe } from "@/lib/billing-api";
export { BillingSummary, PurchaseResultBanner } from "./billing-summary";

/**
 * Buying: the subscription (SecScan Unlimited since 2026-10-03) and any credit packs on sale
 * (none are, so that section renders nothing).
 *
 * Prices come from the server (GET /api/checkout/packs), never from this file,
 * so the page cannot show a number the checkout will not charge. Until Stripe
 * is configured the server reports `enabled: false`, and every surface renders
 * its `fallback` instead of a button that would fail.
 */

export function useBillingCatalog() {
  return useQuery({ queryKey: ["billing-catalog"], queryFn: getBillingCatalog, staleTime: 5 * 60_000 });
}

export function useBillingStatus(enabled = true) {
  return useQuery({ queryKey: ["billing-status"], queryFn: getBillingStatus, staleTime: 30_000, enabled });
}

function friendly(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err ?? "");
  if (/already_subscribed|already have an active subscription/i.test(msg)) return "You already have a subscription — manage it from Settings.";
  if (/failed to fetch|networkerror/i.test(msg)) return "Could not reach the server. Check your connection and try again.";
  return "Could not start checkout. Please try again.";
}

/** A button that runs one checkout action, with its own pending and error state. */
function ActionButton({
  onRun,
  children,
  primary,
}: {
  onRun: () => Promise<void>;
  children: ReactNode;
  primary?: boolean;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <div className="w-full space-y-1.5">
      <button
        type="button"
        disabled={pending}
        onClick={async () => {
          setPending(true);
          setError(null);
          try {
            await onRun(); // navigates away to Stripe on success
          } catch (err) {
            setError(friendly(err));
            setPending(false);
          }
        }}
        className={cn(
          "w-full py-2.5 rounded-lg font-semibold text-sm flex items-center justify-center gap-2 transition-colors disabled:opacity-60",
          primary
            ? "bg-primary text-primary-foreground hover:shadow-[0_0_20px_rgba(20,184,120,0.35)]"
            : "bg-secondary text-foreground border border-white/10 hover:bg-white/10",
        )}
      >
        {pending ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
        {pending ? "Opening checkout…" : children}
      </button>
      {error && <p className="text-xs text-red-400 text-center">{error}</p>}
    </div>
  );
}

/** What every plan includes, beside its own site and scan allowance. */
const PLAN_FEATURES = [
  "Hourly uptime, header and certificate checks",
  "Hourly CVE matching on the software your site runs",
  "Rescans that tighten as your grade drops",
  "Cancel any time from Settings",
];

/**
 * The plans on sale and any credit packs, with Subscribe / Buy buttons.
 *
 * Signed-out visitors (the landing page) get links to create an account
 * instead: checkout needs an account to attach the purchase to.
 */
export function BuyOptions({
  fallback,
  compact,
  packsOnly,
}: {
  fallback?: ReactNode;
  compact?: boolean;
  /** Credits only — for a subscriber topping up, who must not be re-sold a plan. */
  packsOnly?: boolean;
}) {
  const catalog = useBillingCatalog();
  const auth = useGetCurrentAuthUser();
  // A registered account, not merely "has an identity": first-time visitors get
  // a browser-only account with no email, and the server refuses checkout for
  // those (account_required) — a purchase on one would die with the browser.
  const signedIn = !!auth.data?.user?.email;
  const status = useBillingStatus(!!auth.data?.user);

  if (catalog.isLoading) {
    return (
      <div className="flex justify-center py-6">
        <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
      </div>
    );
  }
  if (!catalog.data?.enabled) return <>{fallback ?? null}</>;

  const { plans, packs } = catalog.data;
  const hasPlan = status.data?.subscription && status.data.subscription.status !== "cancelled";
  // The priciest pack per scan is the baseline a bigger pack's discount is measured from.
  const basePerScan = packs.length > 0 ? Math.max(...packs.map((p) => perScanCents(p))) : 0;
  const topPlan = plans[plans.length - 1];
  // "Best value" only means something next to another plan.
  const compareable = plans.length > 1;

  const cta = (run: () => Promise<void>, label: string, primary?: boolean) =>
    signedIn ? (
      <ActionButton onRun={run} primary={primary}>
        {label}
      </ActionButton>
    ) : (
      <Link
        href="/register"
        className={cn(
          "w-full py-2.5 rounded-lg font-semibold text-sm text-center block",
          primary ? "bg-primary text-primary-foreground" : "bg-secondary text-foreground border border-white/10",
        )}
      >
        {primary ? "Create an account to subscribe" : "Sign up to buy"}
      </Link>
    );

  return (
    <div className="space-y-6">
      {/* The subscriptions — the way to save, so they lead. */}
      {!packsOnly && (
        <div
          className={cn(
            "grid gap-5",
            compact || plans.length === 1 ? "grid-cols-1" : "grid-cols-1 md:grid-cols-2",
            plans.length === 1 && !compact && "max-w-md mx-auto",
          )}
        >
          {plans.map((plan) => {
            const featured = plan.key === topPlan?.key;
            return (
              <div
                key={plan.key}
                className={cn(
                  "glass-panel rounded-2xl p-6 flex flex-col relative",
                  featured ? "border border-primary/50 shadow-[0_0_30px_rgba(20,184,120,0.08)]" : "border border-white/10",
                )}
              >
                {featured && compareable && (
                  <div className="absolute top-0 left-6 -translate-y-1/2 bg-primary text-primary-foreground px-3 py-0.5 rounded-full text-[11px] font-bold uppercase tracking-wider">
                    Best value
                  </div>
                )}
                <div className="flex items-center gap-2 mb-1">
                  <Bell className={cn("w-5 h-5", featured ? "text-primary" : "text-muted-foreground")} />
                  <h3 className="text-lg font-bold">{plan.name}</h3>
                </div>
                <div className="flex items-baseline gap-1 mb-1">
                  <span className="text-4xl font-bold tabular-nums">{formatUsd(plan.amountCents)}</span>
                  <span className="text-muted-foreground text-sm">/ month</span>
                </div>
                <p className="text-xs text-muted-foreground mb-4 tabular-nums">
                  {/* Not "no scan limit": scans are uncounted but still rate-limited, as the line below says. */}
                  {planPerScanLabel(plan) ?? "No monthly scan count"}
                </p>
                <ul className="space-y-2 mb-6 flex-1 text-sm">
                  {[
                    plan.urlLimit === 1 ? "1 site watched around the clock" : `Up to ${plan.urlLimit} sites watched around the clock`,
                    planScansLine(plan, catalog.data.scanLimits),
                    ...PLAN_FEATURES,
                  ].map((f) => (
                    <li key={f} className="flex items-start gap-2">
                      <CheckCircle2 className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
                {hasPlan ? (
                  <p className="text-sm text-primary font-medium text-center py-2.5">You&apos;re subscribed — manage it in Settings.</p>
                ) : (
                  cta(() => subscribe(plan.key), `Subscribe — ${formatUsd(plan.amountCents)}/month`, featured)
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Credit packs — for one-off needs, never expire. None are on sale now, so this renders nothing. */}
      {packs.length > 0 && (
      <div className="space-y-3">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Package className="w-4 h-4" /> Or buy scan credits — no subscription, and they never expire
        </div>
        <div className={cn("grid gap-3", compact || packsOnly ? "grid-cols-1" : "grid-cols-1 md:grid-cols-2")}>
          {packs.map((pack) => {
            const saving = Math.round((1 - perScanCents(pack) / basePerScan) * 100);
            return (
              <div
                key={pack.tier}
                className="glass-panel rounded-xl p-4 border border-white/10 flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4"
              >
                <div className="flex-1 min-w-0">
                  <div className="font-semibold whitespace-nowrap">
                    {pack.credits} scans
                    {saving > 0 && <span className="text-primary text-xs font-semibold ml-2">{saving}% off</span>}
                  </div>
                  <div className="text-xs text-muted-foreground tabular-nums">
                    {formatUsd(pack.amountCents)} · {formatUsd(perScanCents(pack))} per scan
                  </div>
                </div>
                <div className="shrink-0 w-full sm:w-32">{cta(() => buyPack(pack.tier), `Buy ${formatUsd(pack.amountCents)}`)}</div>
              </div>
            );
          })}
        </div>
      </div>
      )}
    </div>
  );
}