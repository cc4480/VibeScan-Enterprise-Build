import { useState, type FormEvent } from "react";
import { Link, useLocation } from "wouter";
import { useQueryClient } from "@tanstack/react-query";
import { useSeo } from "@/lib/seo";
import { AuthShell, AuthForm, Field } from "@/components/auth-shell";
import { signIn, accountErrorMessage } from "@/lib/account-api";
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
  // Seeded from the URL so a redirect back from a failed Google attempt lands
  // with the reason already on screen; typing in the form clears it as usual.
  const [error, setError] = useState<string | null>(() =>
    typeof window === "undefined" ? null : googleErrorMessage(window.location.search),
  );
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await signIn(email, password);
      // The signed-in identity differs from the anonymous one the cache was
      // filled with, so drop everything rather than show the previous user's
      // scans until each query happens to refetch.
      await queryClient.invalidateQueries();
      setLocation("/dashboard");
    } catch (err) {
      setError(accountErrorMessage(err, "Could not sign you in. Try again."));
      setSubmitting(false);
    }
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
        onSubmit={handleSubmit}
        error={error}
        submitting={submitting}
        submitLabel="Sign in"
        submittingLabel="Signing in…"
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
