import { useState, type FormEvent } from "react";
import { Link, useLocation } from "wouter";
import { useQueryClient } from "@tanstack/react-query";
import { useSeo } from "@/lib/seo";
import { AuthShell, AuthForm, Field } from "@/components/auth-shell";
import { register, accountErrorMessage } from "@/lib/account-api";
import { GoogleButton, AuthDivider } from "@/components/google-button";

const MIN_PASSWORD_LENGTH = 10;

export default function RegisterPage() {
  useSeo({ title: "Create an account — SecScan", noindex: true });

  const [, setLocation] = useLocation();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Checked here only to save a round trip; the server enforces it regardless.
  const tooShort = password.length > 0 && password.length < MIN_PASSWORD_LENGTH;

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await register(email, password);
      await queryClient.invalidateQueries();
      setLocation("/dashboard");
    } catch (err) {
      setError(accountErrorMessage(err, "Could not create the account. Try again."));
      setSubmitting(false);
    }
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
        submitLabel="Create account"
        submittingLabel="Creating account…"
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
    </AuthShell>
  );
}
