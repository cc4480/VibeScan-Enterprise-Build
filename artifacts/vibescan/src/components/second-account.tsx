/**
 * The second account for access-control testing: two ordinary users who own different data,
 * compared against each other and against a visitor with no session.
 *
 * It takes the same two forms as the first account. Pasting a session works for anyone;
 * "Sign in for me" is the easy path when the first account also signs in with a form,
 * because the sign-in page is the same and only a second username and password are needed.
 */
import type { CredentialMode, ScanCredentialsValue } from "@/components/scan-credentials-fields";

export interface SecondAccountValue {
  enabled: boolean;
  /** Let the scan create the second account itself through the site's signup form. Off unless chosen. */
  autoCreate: boolean;
  mode: CredentialMode;
  cookie: string;
  bearerToken: string;
  loginUrl: string;
  username: string;
  password: string;
}

export const emptySecondAccount: SecondAccountValue = {
  enabled: false,
  autoCreate: false,
  mode: "session",
  cookie: "",
  bearerToken: "",
  loginUrl: "",
  username: "",
  password: "",
};

/** The sign-in page this account will use: its own if given, else the first account's. */
export function secondLoginUrl(v: SecondAccountValue, primary?: ScanCredentialsValue): string {
  return v.loginUrl.trim() || (primary?.mode === "form" ? primary.loginUrl.trim() : "");
}

/** A second account is usable once it can prove who it is: a session, or a sign-in. */
export function secondAccountReady(v: SecondAccountValue, primary?: ScanCredentialsValue): boolean {
  if (!v.enabled || v.autoCreate) return false;
  if (v.mode === "session") return v.cookie.trim() !== "" || v.bearerToken.trim() !== "";
  return v.username.trim() !== "" && v.password !== "" && secondLoginUrl(v, primary) !== "";
}

/** True when the person chose to let the scan create the second account itself. */
export function autoAccountRequested(v: SecondAccountValue): boolean {
  return v.enabled && v.autoCreate;
}

/** What is sent to the server for the second account; the caller has checked it is ready. */
export function secondCredentialsPayload(v: SecondAccountValue, primary?: ScanCredentialsValue) {
  if (v.mode === "session") {
    return {
      mode: "session" as const,
      authorized: true,
      cookie: v.cookie.trim() || null,
      bearerToken: v.bearerToken.trim() || null,
    };
  }
  return {
    mode: "form" as const,
    authorized: true,
    loginUrl: secondLoginUrl(v, primary),
    username: v.username.trim(),
    password: v.password,
  };
}

const inputClass =
  "w-full px-3 py-2.5 rounded-lg bg-secondary border border-white/10 text-sm outline-none focus:border-primary/60 focus:ring-2 focus:ring-primary/20 transition-colors";

export function SecondAccountFields({
  value,
  onChange,
  primary,
}: {
  value: SecondAccountValue;
  onChange: (next: SecondAccountValue) => void;
  primary: ScanCredentialsValue;
}) {
  const set = <K extends keyof SecondAccountValue>(key: K, v: SecondAccountValue[K]) => onChange({ ...value, [key]: v });
  const inherited = primary.mode === "form" && primary.loginUrl.trim() !== "" && value.loginUrl.trim() === "";

  return (
    <div className="flex flex-col gap-3 pt-1 border-t border-white/5">
      <label className="flex items-start gap-2.5 cursor-pointer pt-3">
        <input
          type="checkbox"
          checked={value.enabled}
          onChange={(e) => set("enabled", e.target.checked)}
          className="mt-0.5 w-4 h-4 accent-[var(--primary)]"
        />
        <span className="text-sm leading-relaxed">
          Also check whether one account can read another's data
          <span className="block text-xs text-muted-foreground mt-0.5">
            Add a second account and we'll request the same records as both, and as a visitor with no session. Broken
            access control is the most exploited flaw on the web, and it can only be found by comparing two users.
          </span>
        </span>
      </label>

      {value.enabled ? (
        <div className="flex flex-col gap-3 pl-6">
          <div className="flex gap-2">
            {([{ id: "session", label: "I have a session" }, { id: "form", label: "Sign in for me" }, { id: "auto", label: "Create one for me" }] as const).map((m) => (
              <button
                key={m.id}
                type="button"
                onClick={() => (m.id === "auto" ? onChange({ ...value, autoCreate: true }) : onChange({ ...value, autoCreate: false, mode: m.id }))}
                className={
                  "px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors " +
                  ((m.id === "auto" ? value.autoCreate : !value.autoCreate && value.mode === m.id) ? "border-primary/60 bg-primary/10 text-foreground" : "border-white/10 text-muted-foreground hover:text-foreground")
                }
              >
                {m.label}
              </button>
            ))}
          </div>

          {value.autoCreate ? (
            <div className="flex flex-col gap-2 text-xs text-muted-foreground leading-relaxed">
              <p>
                The scan submits your site's public signup form <strong className="text-foreground">once</strong>, with a made-up
                address at example.com (a domain reserved so it never delivers mail), and uses the new account only for the
                comparison.
              </p>
              <p>
                It works only if signing up gives a signed-in session straight away. If your site asks for email confirmation, or
                the form can't be found, nothing is used and the report says so. If an account is created, the report names it so
                you can delete it. Only choose this for a site you own.
              </p>
            </div>
          ) : value.mode === "session" ? (
            <>
              <label className="flex flex-col gap-1.5">
                <span className="text-sm font-medium">Second account cookie</span>
                <input className={inputClass} placeholder="session=def456" value={value.cookie} onChange={(e) => set("cookie", e.target.value)} autoComplete="off" spellCheck={false} />
              </label>
              <label className="flex flex-col gap-1.5">
                <span className="text-sm font-medium">Second account bearer token</span>
                <input className={inputClass} value={value.bearerToken} onChange={(e) => set("bearerToken", e.target.value)} autoComplete="off" spellCheck={false} />
              </label>
            </>
          ) : (
            <>
              <label className="flex flex-col gap-1.5">
                <span className="text-sm font-medium">Sign-in page URL</span>
                <input
                  className={inputClass}
                  placeholder={inherited ? primary.loginUrl : "https://your-app.com/login"}
                  value={value.loginUrl}
                  onChange={(e) => set("loginUrl", e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                />
                <span className="text-xs text-muted-foreground">
                  {inherited ? "Left blank, the first account's sign-in page is used." : "Must be HTTPS."}
                </span>
              </label>
              <label className="flex flex-col gap-1.5">
                <span className="text-sm font-medium">Second account username</span>
                <input className={inputClass} value={value.username} onChange={(e) => set("username", e.target.value)} autoComplete="off" />
              </label>
              <label className="flex flex-col gap-1.5">
                <span className="text-sm font-medium">Second account password</span>
                <input type="password" className={inputClass} value={value.password} onChange={(e) => set("password", e.target.value)} autoComplete="new-password" />
              </label>
            </>
          )}
          <p className="text-xs text-muted-foreground leading-relaxed">
            Use two ordinary accounts that own different data, not an administrator and a user, which are <em>supposed</em> to see different things.
          </p>
        </div>
      ) : null}
    </div>
  );
}
