import { useEffect, useRef, useState } from "react";
import { Link } from "wouter";
import { useQueryClient } from "@tanstack/react-query";
import { customFetch, useGetCurrentAuthUser } from "@workspace/api-client-react";
import { AlertCircle, CheckCircle2, Loader2 } from "lucide-react";
import { useSeo } from "@/lib/seo";
import { AuthShell } from "@/components/auth-shell";
import { clearTokenFromUrl, tokenInUrl } from "@/lib/url-token";
import { signInForInvite, teamRefusal } from "@/lib/team";

/**
 * The page an invitation email links to. The invitation only works for the address it was sent to, so someone signed out is
 * sent to sign in (and brought back here with the invitation intact), and someone signed in with another address is told so
 * in the server's words. The token is used once and then removed from the address bar.
 */
export default function TeamAcceptPage() {
  useSeo({ title: "Accept your invitation — SecScan.us", noindex: true });
  const queryClient = useQueryClient();
  const { data, isLoading } = useGetCurrentAuthUser();
  const [token] = useState(() => (typeof window === "undefined" ? "" : tokenInUrl(window)));
  const [state, setState] = useState<"working" | "done" | "failed">("working");
  const [error, setError] = useState<string | null>(null);
  // The invitation is single-use: a double invocation would spend it and then report failure on the second call.
  const started = useRef(false);

  const signedIn = Boolean(data?.user);
  useEffect(() => {
    if (isLoading || !signedIn || started.current) return;
    started.current = true;
    clearTokenFromUrl(window);
    if (!token) { setError("That link is missing its invitation. Open the link from your email directly."); setState("failed"); return; }
    customFetch("/api/team/accept", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token }) })
      .then(async () => { await queryClient.invalidateQueries({ queryKey: ["team-shared"] }); setState("done"); })
      .catch((err: unknown) => { setError(teamRefusal(err)); setState("failed"); });
  }, [isLoading, signedIn, token, queryClient]);

  if (isLoading) {
    return <AuthShell title="Your invitation"><div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="w-4 h-4 animate-spin" /> One moment…</div></AuthShell>;
  }

  if (!signedIn) {
    return (
      <AuthShell title="You have been invited">
        <p className="text-sm text-muted-foreground mb-5">
          Someone invited you to read their security reports on SecScan. Sign in with the email address the invitation was sent to, or create an account with it, to accept.
        </p>
        <div className="flex flex-wrap gap-3">
          <Link href={token ? signInForInvite(token) : "/sign-in"} className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium">Sign in</Link>
          <Link href="/register" className="px-4 py-2 border border-white/15 rounded-lg text-sm font-medium">Create an account</Link>
        </div>
        <p className="text-xs text-muted-foreground mt-4">After creating an account, open the link in your email again.</p>
      </AuthShell>
    );
  }

  if (state === "working") {
    return <AuthShell title="Accepting your invitation"><div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="w-4 h-4 animate-spin" /> One moment…</div></AuthShell>;
  }

  if (state === "done") {
    return (
      <AuthShell title="You are on the team">
        <div className="flex items-start gap-3 text-sm">
          <CheckCircle2 className="w-5 h-5 text-green-400 shrink-0 mt-0.5" />
          <p className="text-muted-foreground">You can now read their reports and monitored sites, and download evidence packs; an editor can also pause monitors and file tickets. You will find them under Settings, Team, Shared with you.</p>
        </div>
        <Link href="/settings" className="inline-block mt-5 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium">Go to Settings</Link>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="That did not work">
      <div className="flex items-start gap-3 text-sm">
        <AlertCircle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <p className="text-muted-foreground">{error}</p>
      </div>
      <Link href="/dashboard" className="inline-block mt-5 text-sm text-primary hover:underline">Back to your dashboard</Link>
    </AuthShell>
  );
}
