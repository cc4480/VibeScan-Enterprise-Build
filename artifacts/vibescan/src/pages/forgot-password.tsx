import { useState, type FormEvent } from "react";
import { Link } from "wouter";
import { useSeo } from "@/lib/seo";
import { AuthShell, AuthForm, Field } from "@/components/auth-shell";
import { requestPasswordReset, accountErrorMessage } from "@/lib/account-api";

export default function ForgotPasswordPage() {
  useSeo({ title: "Reset your password — Seclayer", noindex: true });

  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await requestPasswordReset(email);
      setSent(true);
    } catch (err) {
      // Only a transport or rate-limit failure reaches here; the endpoint
      // answers the same way whether or not the address has an account.
      setError(accountErrorMessage(err, "Could not send the reset link. Try again."));
    } finally {
      setSubmitting(false);
    }
  }

  if (sent) {
    return (
      <AuthShell
        title="Check your email"
        subtitle="If that address has an account, a reset link is on its way. The link works once and expires in an hour."
        footer={
          <Link href="/sign-in" className="text-primary hover:underline underline-offset-4">
            Back to sign in
          </Link>
        }
      >
        <p className="text-sm text-muted-foreground leading-relaxed">
          Nothing arrived after a few minutes? Check your spam folder, then{" "}
          <button
            type="button"
            onClick={() => setSent(false)}
            className="text-primary hover:underline underline-offset-4"
          >
            try again
          </button>
          .
        </p>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="Reset your password"
      subtitle="We'll email you a link to choose a new one."
      footer={
        <Link href="/sign-in" className="text-primary hover:underline underline-offset-4">
          Back to sign in
        </Link>
      }
    >
      <AuthForm
        onSubmit={handleSubmit}
        error={error}
        submitting={submitting}
        submitLabel="Send reset link"
        submittingLabel="Sending…"
      >
        <Field
          label="Email"
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
      </AuthForm>
    </AuthShell>
  );
}
