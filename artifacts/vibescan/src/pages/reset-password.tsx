import { useState, type FormEvent } from "react";
import { Link, useLocation } from "wouter";
import { useSeo } from "@/lib/seo";
import { AuthShell, AuthForm, Field } from "@/components/auth-shell";
import { resetPassword, accountErrorMessage } from "@/lib/account-api";

const MIN_PASSWORD_LENGTH = 10;

function tokenFromUrl(): string {
  if (typeof window === "undefined") return "";
  return new URLSearchParams(window.location.search).get("token") ?? "";
}

export default function ResetPasswordPage() {
  useSeo({ title: "Choose a new password — Seclayer", noindex: true });

  const [, setLocation] = useLocation();
  // Read once on mount: the value comes from the emailed link and does not
  // change while the page is open.
  const [token] = useState(tokenFromUrl);
  const [password, setPassword] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const tooShort = password.length > 0 && password.length < MIN_PASSWORD_LENGTH;

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await resetPassword(token, password);
      setDone(true);
    } catch (err) {
      setError(accountErrorMessage(err, "Could not reset the password. Request a new link."));
    } finally {
      setSubmitting(false);
    }
  }

  if (!token) {
    return (
      <AuthShell
        title="That link is incomplete"
        subtitle="The reset link is missing its token. Open the link from your email directly, or request a new one."
        footer={
          <Link href="/forgot-password" className="text-primary hover:underline underline-offset-4">
            Request a new link
          </Link>
        }
      >
        <div />
      </AuthShell>
    );
  }

  if (done) {
    return (
      <AuthShell
        title="Password updated"
        subtitle="Any other devices signed into this account have been signed out."
      >
        <button
          type="button"
          onClick={() => setLocation("/sign-in")}
          className="w-full px-4 py-2.5 bg-primary text-primary-foreground rounded-lg text-sm font-semibold"
        >
          Sign in
        </button>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="Choose a new password" subtitle="This link can only be used once.">
      <AuthForm
        onSubmit={handleSubmit}
        error={error}
        submitting={submitting}
        disabled={tooShort}
        submitLabel="Update password"
        submittingLabel="Updating…"
      >
        <Field
          label="New password"
          type="password"
          autoComplete="new-password"
          required
          minLength={MIN_PASSWORD_LENGTH}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          hint={`At least ${MIN_PASSWORD_LENGTH} characters.`}
        />
      </AuthForm>
    </AuthShell>
  );
}
