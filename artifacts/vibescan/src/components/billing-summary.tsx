/** The billing summary card and the purchase-result banner. */
import { useState } from "react";
import { CheckCircle2, CreditCard, Loader2, Zap } from "lucide-react";
import { cn } from "@/lib/utils";
import { openBillingPortal, planDisplayName, type BillingStatus } from "@/lib/billing-api";
import { useBillingStatus, useBillingCatalog, BuyOptions } from "./billing-options";

export function statusLabel(s: NonNullable<BillingStatus["subscription"]>): { text: string; tone: string } {
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
  const catalog = useBillingCatalog();
  const [portalError, setPortalError] = useState<string | null>(null);

  if (status.isLoading) {
    return <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />;
  }
  if (!status.data) return <p className="text-sm text-muted-foreground">Billing is unavailable right now.</p>;

  const d = status.data;
  const sub = d.subscription;
  const label = sub ? statusLabel(sub) : null;
  const live = !!sub && sub.status !== "cancelled";
  // An unlimited plan has no counter, so a number would read as "0 left". Credits are no longer
  // sold, so their tile is shown only to someone who still holds some.
  const tiles = [
    { n: d.freeScansRemaining as string | number, l: "free scans left this month" },
    live
      ? sub.unlimitedScans
        ? { n: "Unlimited", l: "scans on your plan" }
        : { n: sub.includedScansRemaining, l: "plan scans left" }
      : { n: "—", l: "plan scans left" },
    ...(d.credits > 0 ? [{ n: d.credits, l: "credits" }] : []),
  ];
  // Packs are not sold, so "buy credits" has nothing to show and the prompt is left out.
  const packsOnSale = (catalog.data?.packs.length ?? 0) > 0;

  return (
    <div className="space-y-5">
      <div className={cn("grid gap-3 text-center", tiles.length === 3 ? "grid-cols-3" : "grid-cols-2")}>
        {tiles.map((x) => (
          <div key={x.l} className="rounded-xl border border-white/10 bg-background/40 py-3">
            <div className="text-2xl font-bold tabular-nums">{x.n}</div>
            <div className="text-[11px] uppercase tracking-wider text-muted-foreground">{x.l}</div>
          </div>
        ))}
      </div>

      {sub && label ? (
        <div className="rounded-xl border border-white/10 p-4 flex flex-wrap items-center gap-3">
          <Zap className="w-4 h-4 text-primary" />
          <span className="font-semibold">{planDisplayName(sub.plan)}</span>
          <span className={cn("text-xs px-2 py-0.5 rounded-full border", label.tone)}>{label.text}</span>
          {sub.currentPeriodEnd && sub.status !== "cancelled" && (
            <span className="text-xs text-muted-foreground">
              Renews {new Date(sub.currentPeriodEnd).toLocaleDateString()}
              {sub.unlimitedScans ? "" : " · scans reset then"}
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
      {sub && sub.status !== "cancelled" && packsOnSale && !sub.unlimitedScans && (
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
      ? "Your subscription is active. It starts as soon as Stripe confirms the payment — usually a few seconds."
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
