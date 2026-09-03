import { useState, type FormEvent } from "react";
import { Link, useLocation } from "wouter";
import { useQueryClient } from "@tanstack/react-query";
import { useSeo } from "@/lib/seo";
import { AuthShell, AuthForm, Field } from "@/components/auth-shell";
import { signIn, accountErrorMessage } from "@/lib/account-api";

export default function SignInPage() {
  useSeo({ title: "Sign in — Seclayer", noindex: true });

  const [, setLocation] = useLocation();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
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
