/** The scan form's side panels: active-testing status, trial-exhausted, notify-me, and the friendly error. */
import { Lock, CheckCircle2, Loader2, ShieldCheck, ShieldAlert } from "lucide-react";
import { Link } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { listDomainVerifications } from "@/lib/domain-verification-api";
import { getPurchaseIntent, registerPurchaseIntent } from "@/lib/purchase-intent-api";
import { BuyOptions, useBillingCatalog } from "@/components/billing-options";

/**
 * Whether the domain in the URL box has been proven to belong to this user.
 *
 * This is not decoration. lib/activeProbeGate.ts withholds EVERY active probe —
 * injection, traversal, access control, SSRF, Supabase/Firebase exposure — until
 * ownership is proven, and before this existed the form said the opposite: that
 * the scan "sends real probe traffic to the target, including injection
 * payloads and a port scan". For an unverified domain that was simply untrue,
 * and the only place a user found out was an INFO finding in the finished
 * report, after waiting for the scan.
 *
 * Matching is exact and deliberately so, because the gate's lookup is exact:
 * verifying example.com does NOT unlock www.example.com. Telling someone their
 * domain is verified when the gate will disagree would be worse than saying
 * nothing.
 */
export function domainOf(rawUrl: string): string | null {
  const raw = (rawUrl || "").trim();
  if (!raw) return null;
  try {
    return new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function ActiveTestingStatus({ url }: { url: string }) {
  const domain = domainOf(url);
  const { data: verifications, isLoading } = useQuery({
    queryKey: ["domain-verifications"],
    queryFn: listDomainVerifications,
    staleTime: 60_000,
  });

  if (!domain) return null;

  const verified = (verifications ?? []).some((v) => v.verified && v.domain === domain);

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-xs text-muted-foreground ml-1">
        <Loader2 className="w-3.5 h-3.5 animate-spin shrink-0" />
        Checking whether {domain} is verified…
      </div>
    );
  }

  if (verified) {
    return (
      <div className="flex items-start gap-2 rounded-xl border border-primary/20 bg-primary/5 p-3">
        <ShieldCheck className="w-4 h-4 text-primary mt-0.5 shrink-0" />
        <p className="text-xs text-muted-foreground">
          <span className="font-semibold text-foreground">{domain} is verified.</span>{" "}
          This scan runs the full suite, including injection, path traversal, broken access
          control and backend-exposure testing.
        </p>
      </div>
    );
  }

  return (
    <div className="flex items-start gap-2 rounded-xl border border-amber-500/25 bg-amber-500/5 p-3">
      <ShieldAlert className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
      <p className="text-xs text-muted-foreground">
        <span className="font-semibold text-foreground">Passive checks only for {domain}.</span>{" "}
        Active testing — SQL injection, XSS, path traversal, broken access control, SSRF and
        Supabase/Firebase exposure — is withheld until you prove you control this domain, because
        it sends real attack traffic.{" "}
        <Link href="/domains" className="text-primary underline underline-offset-2 font-medium">
          Verify {domain}
        </Link>{" "}
        with a DNS record or a file, then scan again. Verification is per exact hostname.
      </p>
    </div>
  );
}

/**
 * What someone sees when they run out of free scans.
 *
 * This replaces a one-line red error telling them to "check back shortly",
 * which was a dead end at the single best moment the product gets: they have
 * used it enough to run out. With payments configured it sells the plan and
 * the packs right here; without, it says what they will cost and offers to
 * email when they can be bought — never a purchase page that is not there.
 */
export function TrialExhaustedPanel() {
  // Once Stripe is configured this is where people buy — the single best
  // moment the product gets, because they have used it enough to run out.
  // Until then the server reports payments disabled and the "tell me when"
  // flow below still runs, so the panel is never a dead end either way.
  const catalog = useBillingCatalog();
  if (!catalog.data?.enabled) return <NotifyWhenBuyablePanel />;

  return (
    <div className="rounded-xl border border-primary/25 bg-primary/5 p-5 space-y-5">
      <div className="flex items-start gap-3">
        <Lock className="w-5 h-5 text-primary mt-0.5 shrink-0" />
        <div className="space-y-1">
          <p className="font-semibold text-foreground">That was your last free scan</p>
          <p className="text-sm text-muted-foreground">
            Keep going with the unlimited plan: unlimited scans plus monitoring for 3 sites.
            Your free scans also renew on the 1st of next month. Your existing reports stay on your{" "}
            <Link href="/dashboard" className="text-primary underline underline-offset-2">dashboard</Link>.
          </p>
        </div>
      </div>
      <BuyOptions compact />
    </div>
  );
}

/** The pre-checkout fallback: say what it will cost, offer to email them. */
export function NotifyWhenBuyablePanel() {
  const queryClient = useQueryClient();
  const status = useQuery({
    queryKey: ["purchase-intent"],
    queryFn: getPurchaseIntent,
    staleTime: 60_000,
  });

  const register = useMutation({
    mutationFn: registerPurchaseIntent,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["purchase-intent"] }),
  });

  const registered = status.data?.registered || register.isSuccess;

  return (
    <div className="rounded-xl border border-primary/25 bg-primary/5 p-5 space-y-4">
      <div className="flex items-start gap-3">
        <Lock className="w-5 h-5 text-primary mt-0.5 shrink-0" />
        <div className="space-y-1">
          <p className="font-semibold text-foreground">
            That was your last free scan
          </p>
          <p className="text-sm text-muted-foreground">
            {status.data
              ? `You've used this month's ${status.data.scanLimit} free scans — they renew on the 1st.`
              : "You've used this month's free scans — they renew on the 1st."}{" "}
            The paid plan will be <span className="text-foreground font-medium">$19/month</span> for
            unlimited scans and monitoring for 3 sites. There's
            no way to buy yet — so rather than send you to a checkout that doesn't exist,
            we'll email you the moment there is.
          </p>
        </div>
      </div>

      {registered ? (
        <div className="flex items-start gap-2 rounded-lg border border-primary/20 bg-background/40 p-3">
          <CheckCircle2 className="w-4 h-4 text-primary mt-0.5 shrink-0" />
          <p className="text-xs text-muted-foreground">
            <span className="font-medium text-foreground">You're on the list.</span>{" "}
            We'll email you once scan packs are available. Nothing else — this doesn't
            sign you up for anything.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          <button
            type="button"
            onClick={() => register.mutate()}
            disabled={register.isPending}
            className="w-full py-2.5 rounded-lg bg-primary text-primary-foreground font-medium text-sm disabled:opacity-60 flex items-center justify-center gap-2"
          >
            {register.isPending ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" /> Adding you…
              </>
            ) : (
              "Email me when I can buy scans"
            )}
          </button>
          {register.isError && (
            <p className="text-red-400 text-xs text-center">
              {getFriendlyError(register.error)}
            </p>
          )}
        </div>
      )}

      <p className="text-xs text-muted-foreground">
        Your existing reports stay available on your{" "}
        <Link href="/dashboard" className="text-primary underline underline-offset-2">
          dashboard
        </Link>
        .
      </p>
    </div>
  );
}

export function getFriendlyError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err ?? "");
  if (!msg) return "Something went wrong. Please try again.";
  if (/<!DOCTYPE|<html|<head|<body/i.test(msg)) return "Server is unavailable right now. Please wait a moment and try again.";
  if (/failed to fetch|networkerror|load failed/i.test(msg)) return "Could not reach the server. Check your connection and try again.";
  if (/invalid url/i.test(msg)) return msg;
  if (/unauthorized|401/i.test(msg)) return "Session token missing. Please refresh the page and try again.";
  const clean = msg.replace(/^HTTP \d{3} [^:]+:\s*/, "");
  return clean.length > 120 ? clean.slice(0, 120) + "…" : clean;
}

// Every scan is a full scan. This is what one covers — shown rather than
// chosen, so nobody has to guess which depth they need.
export const COVERAGE: { title: string; items: string[] }[] = [
  {
    title: "Configuration",
    items: ["Security headers and CSP", "TLS and certificate grading", "DNS and exposed files"],
  },
  {
    title: "Active testing",
    items: ["Injection and XSS probing", "Path traversal", "API surface discovery"],
  },
  {
    title: "Access control",
    items: ["Broken access control and IDOR", "Server-side request forgery (SSRF)", "Backend storage rules"],
  },
  {
    title: "Reporting",
    items: ["AI security analysis", "Remediation guide", "Re-scan comparison"],
  },
];
