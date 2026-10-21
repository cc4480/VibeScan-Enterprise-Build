import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { customFetch } from "@workspace/api-client-react";
import { Loader2, ShieldCheck, TriangleAlert } from "lucide-react";
import { useSeo } from "@/lib/seo";
import { isReturnFor, isSafeReturn, outcomeOf, whereTo, type ConsentPreview } from "@/lib/oauth-consent";

/**
 * "Allow this app to use your SecScan account?" — the page an AI editor sends the
 * person to when they connect with a sign-in instead of a pasted token.
 *
 * The server checks the request (registered app, exactly-registered return address,
 * PKCE) and hands back a signed consent token; this page only shows it and carries
 * the answer. An invalid app or address is shown here and never redirected to, so a
 * forged link cannot bounce a code to an address the app did not register.
 */

type Phase =
  | { kind: "loading" }
  | { kind: "invalid"; message: string }
  | { kind: "consent"; preview: ConsentPreview }
  | { kind: "sending"; approved: boolean }
  | { kind: "sent"; approved: boolean };

async function readJson(res: Response): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

export default function OAuthAuthorizePage() {
  useSeo({ title: "Connect an app — SecScan.us", noindex: true });
  const [, setLocation] = useLocation();
  const [phase, setPhase] = useState<Phase>({ kind: "loading" });
  const here = typeof window === "undefined" ? "" : window.location.pathname + window.location.search;

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const body = await customFetch<unknown>(`/api/oauth/authorize/preview${window.location.search}`);
        if (cancelled) return;
        const outcome = outcomeOf(200, body, here);
        if (outcome.kind === "back") leave(outcome.url);
        else if (outcome.kind === "consent") setPhase({ kind: "consent", preview: outcome.preview });
        else setPhase({ kind: "invalid", message: "This link is not valid." });
      } catch (e) {
        if (cancelled) return;
        const status = (e as { status?: number }).status ?? 0;
        const data = (e as { data?: unknown }).data ?? null;
        const outcome = outcomeOf(status || 500, data, here);
        if (outcome.kind === "signin") setLocation(outcome.to);
        else setPhase({ kind: "invalid", message: outcome.kind === "invalid" ? outcome.message : "Something went wrong. Try again from your app." });
      }
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /** `expected` is the redirect the consent preview showed; when given, the address must match it. */
  function leave(url: string, expected?: ConsentPreview["redirect"]) {
    const allowed = expected ? isReturnFor(url, expected) : isSafeReturn(url);
    if (!allowed) {
      setPhase({ kind: "invalid", message: "This link is not valid." });
      return;
    }
    window.location.assign(url);
  }

  async function decide(approve: boolean) {
    if (phase.kind !== "consent") return;
    const { preview } = phase;
    setPhase({ kind: "sending", approved: approve });
    try {
      const out = await customFetch<{ redirectUrl?: string }>("/api/oauth/authorize/decision", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ consent: preview.consent, approve }),
      });
      if (!out.redirectUrl) throw new Error("no redirect");
      setPhase({ kind: "sent", approved: approve });
      leave(out.redirectUrl, preview.redirect);
    } catch (e) {
      const data = (e as { data?: { error_description?: string } }).data;
      setPhase({ kind: "invalid", message: data?.error_description ?? "That did not go through. Start again from your app." });
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-10">
      <div className="w-full max-w-md glass-panel rounded-3xl p-8">
        {phase.kind === "loading" && (
          <div className="flex justify-center py-10"><Loader2 className="w-7 h-7 animate-spin text-primary" /></div>
        )}

        {phase.kind === "invalid" && (
          <div className="text-center space-y-3">
            <TriangleAlert className="w-10 h-10 text-amber-400 mx-auto" />
            <h1 className="text-xl font-bold">We can’t connect this app</h1>
            <p className="text-sm text-muted-foreground">{phase.message}</p>
            <p className="text-xs text-muted-foreground">Nothing was shared. You can close this tab.</p>
          </div>
        )}

        {(phase.kind === "consent" || phase.kind === "sending") && (
          <>
            <div className="text-center mb-6">
              <ShieldCheck className="w-10 h-10 text-primary mx-auto mb-3" />
              <h1 className="text-xl font-bold leading-snug">
                {phase.kind === "consent" ? phase.preview.client.name : "Connecting"} wants to use your SecScan account
              </h1>
              {phase.kind === "consent" && <p className="text-sm text-muted-foreground mt-1">Signed in as {phase.preview.account}</p>}
            </div>

            {phase.kind === "consent" && (
              <>
                <p className="text-sm font-semibold mb-2">If you allow it, it can:</p>
                <ul className="text-sm text-muted-foreground space-y-1.5 mb-5 list-disc pl-5">
                  {phase.preview.access.map((line) => <li key={line}>{line}</li>)}
                </ul>
                <p className="text-xs text-muted-foreground mb-5">
                  It never sees your password, and it can’t change your account settings, billing or other tokens. You can disconnect it any time in Settings.
                </p>
                <div className="flex gap-3">
                  <button type="button" onClick={() => decide(false)} className="flex-1 px-4 py-2.5 rounded-xl border border-white/10 text-sm font-semibold hover:bg-white/5">
                    Cancel
                  </button>
                  <button type="button" onClick={() => decide(true)} className="flex-1 px-4 py-2.5 rounded-xl bg-primary text-primary-foreground text-sm font-semibold">
                    Allow
                  </button>
                </div>
                <p className="text-xs text-muted-foreground mt-4 text-center">{whereTo(phase.preview.redirect)}</p>
              </>
            )}
            {phase.kind === "sending" && (
              <div className="flex justify-center py-6"><Loader2 className="w-6 h-6 animate-spin text-primary" /></div>
            )}
          </>
        )}

        {phase.kind === "sent" && (
          <div className="text-center space-y-2 py-4">
            <h1 className="text-xl font-bold">{phase.approved ? "Connected" : "Cancelled"}</h1>
            <p className="text-sm text-muted-foreground">Returning you to your app. If nothing happens, you can close this tab.</p>
          </div>
        )}
      </div>
    </div>
  );
}
