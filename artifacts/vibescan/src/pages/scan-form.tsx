import { useState } from "react";
import { useLocation } from "wouter";
import { useSeo } from "@/lib/seo";
import { useCreateScan } from "@workspace/api-client-react";
import {
  ScanCredentialsFields,
  emptyCredentials,
  credentialsReady,
  emptySecondAccount,
  secondAccountReady,
  type ScanCredentialsValue,
  type SecondAccountValue,
} from "@/components/scan-credentials-fields";
import { Shield, Zap, Globe, Lock, CheckCircle2, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

function getFriendlyError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err ?? "");
  if (!msg) return "Something went wrong. Please try again.";
  if (/<!DOCTYPE|<html|<head|<body/i.test(msg)) return "Server is unavailable right now. Please wait a moment and try again.";
  if (/failed to fetch|networkerror|load failed/i.test(msg)) return "Could not reach the server. Check your connection and try again.";
  if (/invalid url/i.test(msg)) return msg;
  if (/unauthorized|401/i.test(msg)) return "Session token missing. Please refresh the page and try again.";
  const clean = msg.replace(/^HTTP \d{3} [^:]+:\s*/, "");
  return clean.length > 120 ? clean.slice(0, 120) + "…" : clean;
}

// Every scan is a full scan. This is what one covers — shown rather than
// chosen, so nobody has to guess which depth they need.
const COVERAGE: { title: string; items: string[] }[] = [
  {
    title: "Configuration",
    items: ["Security headers and CSP", "TLS and certificate grading", "DNS and exposed files"],
  },
  {
    title: "Active testing",
    items: ["Injection and XSS probing", "Path traversal", "API surface discovery"],
  },
  {
    title: "Access control",
    items: ["Broken access control and IDOR", "Out-of-band SSRF", "Backend storage rules"],
  },
  {
    title: "Reporting",
    items: ["AI security analysis", "Remediation guide", "Re-scan comparison"],
  },
];

export default function ScanFormPage() {
  useSeo({ title: "New Scan — Seclayer", noindex: true });
  const [url, setUrl] = useState("");
  const [credentials, setCredentials] = useState<ScanCredentialsValue>(emptyCredentials);
  const [secondAccount, setSecondAccount] = useState<SecondAccountValue>(emptySecondAccount);
  const [, setLocation] = useLocation();

  const createScan = useCreateScan();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    let targetUrl = url;
    if (!url.trim()) return;
    if (!/^https?:\/\//i.test(targetUrl)) {
      targetUrl = "https://" + targetUrl;
    }

    // Only send credentials when the section was actually filled in and
    // attested — a half-completed form should run a normal scan, not a failed
    // authenticated one.
    const creds = credentialsReady(credentials)
      ? {
          mode: credentials.mode,
          authorized: credentials.authorized,
          ...(credentials.mode === "session"
            ? {
                cookie: credentials.cookie.trim() || null,
                bearerToken: credentials.bearerToken.trim() || null,
              }
            : {
                loginUrl: credentials.loginUrl.trim(),
                username: credentials.username.trim(),
                password: credentials.password,
              }),
        }
      : undefined;

    // A second account only travels with a first one — the server rejects it
    // alone, and access control is a comparison between two identities.
    const secondCreds =
      creds && secondAccountReady(secondAccount)
        ? {
            mode: "session" as const,
            authorized: true,
            cookie: secondAccount.cookie.trim() || null,
            bearerToken: secondAccount.bearerToken.trim() || null,
          }
        : undefined;

    createScan.mutate(
      {
        data: {
          targetUrl,
          ...(creds ? { credentials: creds } : {}),
          ...(secondCreds ? { secondaryCredentials: secondCreds } : {}),
        },
      },
      {
        onSuccess: (data) => {
          setLocation(`/scan/${data.scanId}`);
        },
      },
    );
  };

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="text-center mb-10">
        <div className="w-16 h-16 bg-primary/10 rounded-2xl flex items-center justify-center mx-auto mb-6 border border-primary/20">
          <Shield className="w-8 h-8 text-primary" />
        </div>
        <h1 className="text-3xl md:text-4xl font-bold tracking-tight mb-3">
          Launch Security Scan
        </h1>
        <p className="text-muted-foreground text-lg">
          Paste any publicly accessible URL — your app, a client's site, or any live website.
        </p>
      </div>

      <div className="glass-panel p-6 sm:p-10 rounded-3xl">
        <form onSubmit={handleSubmit} className="flex flex-col gap-10">
          {/* URL Input */}
          <div className="flex flex-col gap-3">
            <label htmlFor="url" className="text-sm font-semibold flex items-center gap-2">
              <Globe className="w-4 h-4 text-primary" /> Target URL
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                <Lock className="w-5 h-5 text-muted-foreground" />
              </div>
              <input
                id="url"
                type="text"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
                className="w-full bg-background border-2 border-white/10 rounded-xl py-4 pl-12 pr-4 text-lg focus:outline-none focus:border-primary focus:ring-4 focus:ring-primary/10 transition-all placeholder:text-muted-foreground/50"
              />
            </div>
            <p className="text-xs text-muted-foreground ml-1">
              Any publicly accessible website works. Only scan sites you have permission to test.
            </p>
          </div>

          {/* What a scan covers — informational, not a choice */}
          <div className="flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <label className="text-sm font-semibold flex items-center gap-2">
                <Zap className="w-4 h-4 text-primary" /> What this scan covers
              </label>
              <span className="text-xs text-muted-foreground">Every check, every scan</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {COVERAGE.map((group) => (
                <div
                  key={group.title}
                  className="flex flex-col p-5 rounded-2xl border-2 border-white/5 bg-secondary/50"
                >
                  <div className="font-bold text-sm mb-3">{group.title}</div>
                  <ul className="flex flex-col gap-1.5">
                    {group.items.map((item) => (
                      <li
                        key={item}
                        className="text-xs flex items-center gap-1.5 text-muted-foreground"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5 text-primary/70 shrink-0" /> {item}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>

            <p className="text-xs text-muted-foreground">
              This scan sends real probe traffic to the target, including injection payloads and
              a port scan. Only scan applications you own or are authorised to test.
            </p>
          </div>

          <ScanCredentialsFields
            value={credentials}
            onChange={setCredentials}
            second={secondAccount}
            onSecondChange={setSecondAccount}
          />

          {/* Submit */}
          <div className="pt-6 border-t border-white/5 flex flex-col items-center gap-4">
            <button
              type="submit"
              disabled={createScan.isPending || !url.trim()}
              className="w-full sm:w-auto min-w-[260px] px-8 py-4 bg-primary text-primary-foreground text-lg font-bold rounded-xl shadow-[0_0_30px_rgba(20,184,120,0.25)] hover:shadow-[0_0_40px_rgba(20,184,120,0.4)] disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 flex items-center justify-center gap-2"
            >
              {createScan.isPending ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" /> Processing...
                </>
              ) : (
                <>
                  <Zap className="w-5 h-5" /> Run Scan
                </>
              )}
            </button>

            {createScan.isError && (
              <p className="text-red-400 text-sm text-center">
                {getFriendlyError(createScan.error)}
              </p>
            )}

            <p className="text-xs text-muted-foreground text-center">
              Only scan sites you own or have explicit permission to test.
            </p>
          </div>
        </form>
      </div>
    </div>
  );
}
