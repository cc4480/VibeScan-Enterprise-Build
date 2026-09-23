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
 * Buying: the SecScan Pro subscription and the credit packs.
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
  if (/already_subscribed|already have an active subscription/i.test(msg)) return "You already have SecScan Pro — manage it from Settings.";
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

/**
 * The plan and the three packs, with Buy / Subscribe buttons.
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
  /** Credits only — for a subscriber topping up, who must not be re-sold the plan they have. */
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

  const { plan, packs } = catalog.data;
  const single = packs.find((p) => p.credits === 1);
  const hasPlan = status.data?.subscription && status.data.subscription.status !== "cancelled";

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
    <div className={cn("grid gap-5", compact || packsOnly ? "grid-cols-1" : "grid-cols-1 lg:grid-cols-[1.15fr_1fr]")}>
      {/* The subscription — the way to save, so it leads. */}
      {!packsOnly && (
      <div className="glass-panel rounded-2xl p-6 border border-primary/50 shadow-[0_0_30px_rgba(20,184,120,0.08)] flex flex-col relative">
        <div className="absolute top-0 left-6 -translate-y-1/2 bg-primary text-primary-foreground px-3 py-0.5 rounded-full text-[11px] font-bold uppercase tracking-wider">
          Best value
        </div>
        <div className="flex items-center gap-2 mb-1">
          <Bell className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-bold">{plan.name}</h3>
        </div>
        <div className="flex items-baseline gap-1 mb-4">
          <span className="text-4xl font-bold tabular-nums">{formatUsd(plan.amountCents)}</span>
          <span className="text-muted-foreground text-sm">/ month</span>
        </div>
        <ul className="space-y-2 mb-6 flex-1 text-sm">
          {[
            `Up to ${plan.urlLimit} sites watched around the clock`,
            `${plan.includedScans} on-demand full scans every month`,
            "Hourly uptime, header and certificate checks",
            "Hourly CVE matching, ranked by exploit likelihood",
            "Rescans that tighten as your grade drops",
            "Cancel any time from Settings",
          ].map((f) => (
            <li key={f} className="flex items-start gap-2">
              <CheckCircle2 className="w-4 h-4 text-primary shrink-0 mt-0.5" />
              <span>{f}</span>
            </li>
          ))}
        </ul>
        {single && (
          <p className="text-xs text-muted-foreground mb-3">
            {plan.includedScans} scans alone would cost {formatUsd(single.amountCents * plan.includedScans)} as single credits.
          </p>
        )}
        {hasPlan ? (
          <p className="text-sm text-primary font-medium text-center py-2.5">You're subscribed — manage it in Settings.</p>
        ) : (
          cta(subscribe, `Subscribe — ${formatUsd(plan.amountCents)}/month`, true)
        )}
      </div>
      )}

      {/* Credit packs — for one-off needs, never expire. */}
      <div className="space-y-3">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Package className="w-4 h-4" /> Or buy scan credits — they never expire
        </div>
        {packs.map((pack) => {
          const saving =
            single && pack.credits > 1
              ? Math.round((1 - perScanCents(pack) / single.amountCents) * 100)
              : 0;
          return (
            <div
              key={pack.tier}
              className={cn(
                "glass-panel rounded-xl p-4 border border-white/10 flex gap-3",
                // Stacked on phones — text above, full-width button below —
                // and side by side once there is room. In the compact column
                // (paywall, Settings) "room" arrives later, so it stays stacked
                // until md.
                compact || packsOnly ? "flex-col md:flex-row md:items-center md:gap-4" : "flex-col sm:flex-row sm:items-center sm:gap-4",
              )}
            >
              <div className="flex-1 min-w-0">
                <div className="font-semibold whitespace-nowrap">
                  {pack.credits} scan{pack.credits === 1 ? "" : "s"}
                  {saving > 0 && <span className="text-primary text-xs font-semibold ml-2">{saving}% off</span>}
                </div>
                <div className="text-xs text-muted-foreground tabular-nums">
                  {pack.credits === 1
                    ? `${formatUsd(pack.amountCents)} per scan`
                    : `${formatUsd(pack.amountCents)} · ${formatUsd(perScanCents(pack))} per scan`}
                </div>
              </div>
              <div className={cn("shrink-0 w-full", compact || packsOnly ? "md:w-32" : "sm:w-32")}>
                {cta(() => buyPack(pack.tier), `Buy ${formatUsd(pack.amountCents)}`)}
              </div>
            </div>
          );
        })}
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
          { n: d.freeScansRemaining, l: "free scans left" },
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
          <span className="font-semibold">SecScan Pro</span>
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
      ? "Welcome to SecScan Pro. Your monthly scans appear as soon as Stripe confirms the payment — usually a few seconds."
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
