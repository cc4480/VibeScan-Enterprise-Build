import { useEffect, useRef, useState } from "react";
import { Link } from "wouter";
import { useSeo } from "@/lib/seo";
import { AuthShell } from "@/components/auth-shell";
import { verifyEmail, accountErrorMessage } from "@/lib/account-api";
import { Loader2, CheckCircle2, AlertCircle } from "lucide-react";

export default function VerifyEmailPage() {
  useSeo({ title: "Confirming your email — Seclayer", noindex: true });

  const [state, setState] = useState<"working" | "done" | "failed">("working");
  const [error, setError] = useState<string | null>(null);
  // The token is single-use, so a double invocation would spend it and then
  // report failure on the second call.
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    const token = new URLSearchParams(window.location.search).get("token") ?? "";
    if (!token) {
      setError("That link is missing its token. Open the link from your email directly.");
      setState("failed");
      return;
    }

    verifyEmail(token)
      .then(() => setState("done"))
      .catch((err: unknown) => {
        setError(accountErrorMessage(err, "That link is no longer valid."));
        setState("failed");
      });
  }, []);

  if (state === "working") {
    return (
      <AuthShell title="Confirming your email">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="w-4 h-4 animate-spin" />
          One moment…
        </div>
      </AuthShell>
    );
  }

  if (state === "done") {
    return (
      <AuthShell
        title="Email confirmed"
        subtitle="You'll get scan results and security alerts at this address."
      >
        <div className="flex items-center gap-2 text-sm text-emerald-400 mb-6">
          <CheckCircle2 className="w-4 h-4" />
          All set
        </div>
        <Link
          href="/dashboard"
          className="inline-block w-full text-center px-4 py-2.5 bg-primary text-primary-foreground rounded-lg text-sm font-semibold"
        >
          Go to dashboard
        </Link>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="That link didn't work"
      subtitle={error ?? undefined}
      footer={
        <Link href="/settings" className="text-primary hover:underline underline-offset-4">
          Send a new confirmation email
        </Link>
      }
    >
      <div className="flex items-center gap-2 text-sm text-red-400">
        <AlertCircle className="w-4 h-4" />
        Confirmation failed
      </div>
    </AuthShell>
  );
}
