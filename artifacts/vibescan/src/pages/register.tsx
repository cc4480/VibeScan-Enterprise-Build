import { useState, type FormEvent } from "react";
import { Link, useLocation } from "wouter";
import { useQueryClient } from "@tanstack/react-query";
import { useSeo } from "@/lib/seo";
import { AuthShell, AuthForm, Field, CheckSpamNote } from "@/components/auth-shell";
import { register, verifyRegistration, accountErrorMessage } from "@/lib/account-api";
import { GoogleButton, AuthDivider } from "@/components/google-button";

const MIN_PASSWORD_LENGTH = 10;

export default function RegisterPage() {
  useSeo({ title: "Create an account — SecScan.us", noindex: true });

  const [, setLocation] = useLocation();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  // Step two. The account does not exist until the emailed code comes back;
  // `challenge` is the handle step one returned, never a credential on its own.
  const [challenge, setChallenge] = useState<string | null>(null);
  const [sentTo, setSentTo] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Checked here only to save a round trip; the server enforces it regardless.
  const tooShort = password.length > 0 && password.length < MIN_PASSWORD_LENGTH;

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const result = await register(email, password);
      setChallenge(result.challenge);
      setSentTo(result.sentTo);
      setCode("");
      setSubmitting(false);
    } catch (err) {
      setError(accountErrorMessage(err, "Could not create the account. Try again."));
      setSubmitting(false);
    }
  }

  async function handleCodeSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!challenge) return;
    setError(null);
    setSubmitting(true);
    try {
      await verifyRegistration(challenge, code.replace(/[\s-]/g, ""));
      await queryClient.invalidateQueries();
      setLocation("/dashboard");
    } catch (err) {
      setError(accountErrorMessage(err, "That code is not valid. Start again to get a new one."));
      setCode("");
      setSubmitting(false);
    }
  }

  // Back to the details step; submitting again sends a new code and retires this one.
  function startOver() {
    setChallenge(null);
    setCode("");
    setError(null);
  }

  // ── Step two: the emailed code ──────────────────────────────────────────────
  if (challenge) {
    return (
      <AuthShell
        title="Confirm your email"
        subtitle={`We sent a 6-digit code to ${sentTo}. It expires in 10 minutes. Your account is created when you enter it.`}
        footer={
          <button type="button" onClick={startOver} className="text-primary hover:underline underline-offset-4">
            Use a different email
          </button>
        }
      >
        <AuthForm
          onSubmit={handleCodeSubmit}
          error={error}
          submitting={submitting}
          submitLabel="Create account"
          submittingLabel="Verifying…"
          disabled={code.replace(/[\s-]/g, "").length !== 6}
        >
          <Field
            label="Confirmation code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={7}
            autoFocus
            required
            placeholder="123456"
            hint="Spaces don't matter. Five wrong tries and you'll need a new code."
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
        </AuthForm>
        <CheckSpamNote what="code" />
        {/* The server answers an address that already has an account exactly as it
            answers a new one, so it cannot be used to find out who is registered.
            This is how someone who does have an account finds out what happened. */}
        <p className="mt-4 text-xs text-muted-foreground text-center leading-relaxed">
          Already have an account with this address? Then there's no code to enter. We've emailed you a link to{" "}
          <Link href="/sign-in" className="text-primary hover:underline underline-offset-4">
            sign in
          </Link>{" "}
          instead.
        </p>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="Create an account"
      subtitle="Scans you've already run on this browser move to your new account automatically."
      footer={
        <>
          Already have an account?{" "}
          <Link href="/sign-in" className="text-primary hover:underline underline-offset-4">
            Sign in
          </Link>
        </>
      }
    >
      <GoogleButton returnTo="/dashboard" label="Sign up with Google" />
      <AuthDivider />

      <AuthForm
        onSubmit={handleSubmit}
        error={error}
        submitting={submitting}
        disabled={tooShort}
        submitLabel="Continue"
        submittingLabel="Sending code…"
      >
        <Field
          label="Email"
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <Field
          label="Password"
          type="password"
          autoComplete="new-password"
          required
          minLength={MIN_PASSWORD_LENGTH}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          hint={
            tooShort
              ? `${MIN_PASSWORD_LENGTH - password.length} more character${
                  MIN_PASSWORD_LENGTH - password.length === 1 ? "" : "s"
                } needed`
              : `At least ${MIN_PASSWORD_LENGTH} characters. Length matters more than symbols.`
          }
        />
      </AuthForm>

      {/* Both sign-up paths are covered: the Google button above creates an
          account too, so this sits outside the form rather than inside it. */}
      <p className="mt-6 text-xs text-muted-foreground text-center leading-relaxed">
        By creating an account you agree to our{" "}
        <Link href="/terms" className="text-primary hover:underline underline-offset-4">
          Terms of Service
        </Link>{" "}
        and{" "}
        <Link href="/privacy" className="text-primary hover:underline underline-offset-4">
          Privacy Policy
        </Link>
        . You may only scan sites you own or have permission to test.
      </p>
    </AuthShell>
  );
}
