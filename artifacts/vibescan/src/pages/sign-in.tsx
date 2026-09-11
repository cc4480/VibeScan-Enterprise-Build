import { useState, type FormEvent } from "react";
import { Link, useLocation } from "wouter";
import { useQueryClient } from "@tanstack/react-query";
import { useSeo } from "@/lib/seo";
import { AuthShell, AuthForm, Field } from "@/components/auth-shell";
import { signIn, verifySignIn, accountErrorMessage } from "@/lib/account-api";
import { GoogleButton, AuthDivider } from "@/components/google-button";

/**
 * Failures during Google sign-in come back as ?error=<code> rather than as a
 * message, so the wording lives here and an edited URL cannot put arbitrary
 * text on the page. An unrecognised code falls back to something honest rather
 * than showing the raw value.
 */
const GOOGLE_ERRORS: Record<string, string> = {
  not_configured:
    "Google sign-in is temporarily unavailable. Please use your email and password, or try again later.",
  rate_limited: "Too many sign-in attempts. Please wait a few minutes and try again.",
  unavailable: "Could not reach Google just now. Please try again in a moment.",
  session_expired: "That sign-in attempt timed out. Please try again.",
  session_malformed: "That sign-in attempt could not be completed. Please try again.",
  no_email: "Google did not share an email address with us, so we could not sign you in.",
  account_conflict:
    "This email is already linked to a different Google account. Sign in with your email and password instead.",
  create_failed: "We could not finish creating your account. Please try again.",
  failed: "Google sign-in did not complete. Please try again.",
};

function googleErrorMessage(search: string): string | null {
  const code = new URLSearchParams(search).get("error");
  if (!code) return null;
  return GOOGLE_ERRORS[code] ?? "Google sign-in did not complete. Please try again.";
}

export default function SignInPage() {
  useSeo({ title: "Sign in — SecScan", noindex: true });

  const [, setLocation] = useLocation();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  // Step two of sign-in. `challenge` is the handle the password step returned;
  // holding it is what lets the emailed code be spent, and it is never a
  // credential on its own.
  const [challenge, setChallenge] = useState<string | null>(null);
  const [sentTo, setSentTo] = useState("");
  const [code, setCode] = useState("");
  // Seeded from the URL so a redirect back from a failed Google attempt lands
  // with the reason already on screen; typing in the form clears it as usual.
  const [error, setError] = useState<string | null>(() =>
    typeof window === "undefined" ? null : googleErrorMessage(window.location.search),
  );
  const [submitting, setSubmitting] = useState(false);

  // Step one. A correct password does not sign anyone in — it returns a
  // challenge and the server emails a code.
  async function handlePasswordSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const result = await signIn(email, password);
      setChallenge(result.challenge);
      setSentTo(result.sentTo);
      setCode("");
      setSubmitting(false);
    } catch (err) {
      setError(accountErrorMessage(err, "Could not sign you in. Try again."));
      setSubmitting(false);
    }
  }

  // Step two. Only this creates a session.
  async function handleCodeSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!challenge) return;
    setError(null);
    setSubmitting(true);
    try {
      await verifySignIn(challenge, code.replace(/[\s-]/g, ""));
      // The signed-in identity differs from the anonymous one the cache was
      // filled with, so drop everything rather than show the previous user's
      // scans until each query happens to refetch.
      await queryClient.invalidateQueries();
      setLocation("/dashboard");
    } catch (err) {
      setError(accountErrorMessage(err, "That code is not valid. Start again to get a new one."));
      setCode("");
      setSubmitting(false);
    }
  }

  // Back to the password step. The challenge is dropped rather than kept for
  // later: the user is about to be issued a new one, which retires this.
  function startOver() {
    setChallenge(null);
    setCode("");
    setPassword("");
    setError(null);
  }

  // ── Step two: the emailed code ──────────────────────────────────────────────
  if (challenge) {
    return (
      <AuthShell
        title="Check your email"
        subtitle={`We sent a 6-digit code to ${sentTo}. It expires in 10 minutes.`}
        footer={
          <button
            type="button"
            onClick={startOver}
            className="text-primary hover:underline underline-offset-4"
          >
            Use a different account
          </button>
        }
      >
        <AuthForm
          onSubmit={handleCodeSubmit}
          error={error}
          submitting={submitting}
          submitLabel="Sign in"
          submittingLabel="Verifying…"
          disabled={code.replace(/[\s-]/g, "").length !== 6}
        >
          <Field
            label="Sign-in code"
            // Not type="number": that renders spinners and can strip a leading
            // zero, and a code is a string of digits rather than a quantity.
            // `one-time-code` lets the browser and phone keyboard offer it
            // straight from the notification.
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            // Room for the "123 456" spacing the email uses; the server strips
            // separators, so pasting it verbatim works.
            maxLength={7}
            autoFocus
            required
            placeholder="123456"
            hint="Spaces don't matter. Five wrong tries and you'll need a new code."
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
        </AuthForm>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="Sign in"
      subtitle="Sign in to reach your scan history from any browser."
      footer={
        <>
          Don't have an account?{" "}
          <Link href="/register" className="text-primary hover:underline underline-offset-4">
            Create one
          </Link>
        </>
      }
    >
      <GoogleButton returnTo="/dashboard" />
      <AuthDivider />

      <AuthForm
        onSubmit={handlePasswordSubmit}
        error={error}
        submitting={submitting}
        submitLabel="Continue"
        submittingLabel="Checking…"
      >
        <Field
          label="Email"
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <div className="flex flex-col gap-1.5">
          <Field
            label="Password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <Link
            href="/forgot-password"
            className="text-xs text-muted-foreground hover:text-foreground self-start"
          >
            Forgot your password?
          </Link>
        </div>
      </AuthForm>
    </AuthShell>
  );
}
