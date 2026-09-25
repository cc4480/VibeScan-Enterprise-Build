import { useState, type ReactNode } from "react";
import { Link } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { useGetCurrentAuthUser } from "@workspace/api-client-react";
import { Bell, CheckCircle2, CreditCard, Loader2, Package, Zap } from "lucide-react";
import { cn } from "@/lib/utils";
import {
  buyPack,
  formatUsd,
  getBillingCatalog,
  getBillingStatus,
  openBillingPortal,
  perScanCents,
  subscribe,
  type BillingStatus,
} from "@/lib/billing-api";

/**
 * Buying: the SecScan Starter and Pro subscriptions, and the credit packs.
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
 * The two plans and the credit packs, with Subscribe / Buy buttons.
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
  const basePerScan = Math.max(...packs.map((p) => perScanCents(p)));
  const topPlan = plans[plans.length - 1];

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
        <div className={cn("grid gap-5", compact ? "grid-cols-1" : "grid-cols-1 md:grid-cols-2")}>
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
                {featured && (
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
                  {formatUsd(Math.round(plan.amountCents / plan.includedScans))} per scan
                </p>
                <ul className="space-y-2 mb-6 flex-1 text-sm">
                  {[
                    plan.urlLimit === 1 ? "1 site watched around the clock" : `Up to ${plan.urlLimit} sites watched around the clock`,
                    `${plan.includedScans} full scans every month`,
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

      {/* Credit packs — for one-off needs, never expire. */}
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
    </div>
  );
}

function statusLabel(s: NonNullable<BillingStatus["subscription"]>): { text: string; tone: string } {
  switch (s.status) {
    case "active":
      return { text: "Active", tone: "text-primary bg-primary/10 border-primary/30" };
    case "past_due":
      return { text: "Payment retrying", tone: "text-amber-300 bg-amber-400/10 border-amber-400/30" };
    case "paused":
      return { text: "Paused — update your card", tone: "text-red-300 bg-red-400/10 border-red-400/30" };
    default:
      return { text: "Cancelled", tone: "text-muted-foreground bg-secondary border-white/10" };
  }
}

/** The account's billing position, for Settings. */
export function BillingSummary() {
  const status = useBillingStatus();
  const [portalError, setPortalError] = useState<string | null>(null);

  if (status.isLoading) {
    return <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />;
  }
  if (!status.data) return <p className="text-sm text-muted-foreground">Billing is unavailable right now.</p>;

  const d = status.data;
  const sub = d.subscription;
  const label = sub ? statusLabel(sub) : null;

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-3 gap-3 text-center">
        {[
          { n: d.freeScansRemaining, l: "free scans left this month" },
          { n: sub && sub.status !== "cancelled" ? sub.includedScansRemaining : "—", l: "plan scans left" },
          { n: d.credits, l: "credits" },
        ].map((x) => (
          <div key={x.l} className="rounded-xl border border-white/10 bg-background/40 py-3">
            <div className="text-2xl font-bold tabular-nums">{x.n}</div>
            <div className="text-[11px] uppercase tracking-wider text-muted-foreground">{x.l}</div>
          </div>
        ))}
      </div>

      {sub && label ? (
        <div className="rounded-xl border border-white/10 p-4 flex flex-wrap items-center gap-3">
          <Zap className="w-4 h-4 text-primary" />
          <span className="font-semibold">{sub.plan === "starter" ? "SecScan Starter" : "SecScan Pro"}</span>
          <span className={cn("text-xs px-2 py-0.5 rounded-full border", label.tone)}>{label.text}</span>
          {sub.currentPeriodEnd && sub.status !== "cancelled" && (
            <span className="text-xs text-muted-foreground">
              Renews {new Date(sub.currentPeriodEnd).toLocaleDateString()} · scans reset then
            </span>
          )}
          {sub.canManage && (
            <button
              type="button"
              onClick={async () => {
                setPortalError(null);
                try {
                  await openBillingPortal();
                } catch {
                  setPortalError("Could not open billing. Please try again.");
                }
              }}
              className="ml-auto inline-flex items-center gap-1.5 text-sm text-primary hover:underline"
            >
              <CreditCard className="w-4 h-4" /> Manage or cancel
            </button>
          )}
          {portalError && <p className="w-full text-xs text-red-400">{portalError}</p>}
        </div>
      ) : null}

      {(!sub || sub.status === "cancelled") && <BuyOptions compact />}
      {sub && sub.status !== "cancelled" && (
        <details className="text-sm">
          <summary className="cursor-pointer text-muted-foreground hover:text-foreground">Need more scans this month? Buy credits</summary>
          <div className="mt-4">
            <BuyOptions compact packsOnly />
          </div>
        </details>
      )}
    </div>
  );
}

/** One-line confirmation after Stripe sends someone back. */
export function PurchaseResultBanner() {
  const params = new URLSearchParams(window.location.search);
  const result = params.get("purchase");
  if (!result) return null;

  const text =
    result === "subscribed"
      ? "Your subscription is active. Your monthly scans appear as soon as Stripe confirms the payment — usually a few seconds."
      : result === "success"
        ? "Payment received. Your credits appear as soon as Stripe confirms it — usually a few seconds."
        : result === "cancelled"
          ? "Checkout cancelled — you weren't charged."
          : null;
  if (!text) return null;

  return (
    <div
      className={cn(
        "mb-6 rounded-xl border px-4 py-3 text-sm flex items-start gap-2",
        result === "cancelled" ? "border-white/10 bg-secondary text-muted-foreground" : "border-primary/30 bg-primary/10 text-foreground",
      )}
    >
      <CheckCircle2 className={cn("w-4 h-4 mt-0.5 shrink-0", result === "cancelled" ? "text-muted-foreground" : "text-primary")} />
      <span>{text}</span>
    </div>
  );
}
