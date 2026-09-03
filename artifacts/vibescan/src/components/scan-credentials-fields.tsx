/**
 * Optional credentials for an authenticated scan.
 *
 * Collapsed by default: most scans are unauthenticated, and the pay-per-scan
 * flow depends on the form staying a URL box. Opening it is a deliberate act,
 * which suits a section where someone types a production password.
 */

import { useState } from "react";
import { ChevronDown, ChevronRight, ShieldAlert } from "lucide-react";

export type CredentialMode = "session" | "form";

export interface ScanCredentialsValue {
  mode: CredentialMode;
  authorized: boolean;
  cookie: string;
  bearerToken: string;
  loginUrl: string;
  username: string;
  password: string;
}

export interface SecondAccountValue {
  enabled: boolean;
  cookie: string;
  bearerToken: string;
}

export const emptySecondAccount: SecondAccountValue = {
  enabled: false,
  cookie: "",
  bearerToken: "",
};

/** A second account is usable once it carries a session of its own. */
export function secondAccountReady(v: SecondAccountValue): boolean {
  return v.enabled && (v.cookie.trim() !== "" || v.bearerToken.trim() !== "");
}

export const emptyCredentials: ScanCredentialsValue = {
  mode: "session",
  authorized: false,
  cookie: "",
  bearerToken: "",
  loginUrl: "",
  username: "",
  password: "",
};

/**
 * Whether the user has supplied enough to attempt an authenticated scan.
 * Mirrors the server's validation so the button disables rather than the
 * request bouncing, but the server remains the authority.
 */
export function credentialsReady(v: ScanCredentialsValue): boolean {
  if (!v.authorized) return false;
  if (v.mode === "session") return v.cookie.trim() !== "" || v.bearerToken.trim() !== "";
  return v.loginUrl.trim() !== "" && v.username.trim() !== "" && v.password !== "";
}

/** True once the user has typed anything at all into the section. */
export function credentialsTouched(v: ScanCredentialsValue): boolean {
  return (
    v.authorized ||
    v.cookie.trim() !== "" ||
    v.bearerToken.trim() !== "" ||
    v.loginUrl.trim() !== "" ||
    v.username.trim() !== "" ||
    v.password !== ""
  );
}

const inputClass =
  "w-full px-3 py-2.5 rounded-lg bg-secondary border border-white/10 text-sm outline-none focus:border-primary/60 focus:ring-2 focus:ring-primary/20 transition-colors";

export function ScanCredentialsFields({
  value,
  onChange,
  second,
  onSecondChange,
}: {
  value: ScanCredentialsValue;
  onChange: (next: ScanCredentialsValue) => void;
  second: SecondAccountValue;
  onSecondChange: (next: SecondAccountValue) => void;
}) {
  const [open, setOpen] = useState(false);
  const set = <K extends keyof ScanCredentialsValue>(key: K, v: ScanCredentialsValue[K]) =>
    onChange({ ...value, [key]: v });

  return (
    <div className="glass-card rounded-2xl overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-2 px-5 py-4 text-left"
        aria-expanded={open}
      >
        {open ? (
          <ChevronDown className="w-4 h-4 text-muted-foreground" />
        ) : (
          <ChevronRight className="w-4 h-4 text-muted-foreground" />
        )}
        <span className="text-sm font-semibold">Scan behind a login</span>
        <span className="text-xs text-muted-foreground ml-1">Optional</span>
        {credentialsTouched(value) && !open ? (
          <span className="ml-auto text-xs text-primary">Configured</span>
        ) : null}
      </button>

      {open ? (
        <div className="px-5 pb-5 flex flex-col gap-4 border-t border-white/5 pt-4">
          <p className="text-sm text-muted-foreground leading-relaxed">
            Without credentials the scan only sees what a signed-out visitor sees. Most of an
            application sits behind its login.
          </p>

          {/* Mode */}
          <div className="flex gap-2">
            {(
              [
                { id: "session", label: "I have a session" },
                { id: "form", label: "Sign in for me" },
              ] as const
            ).map((m) => (
              <button
                key={m.id}
                type="button"
                onClick={() => set("mode", m.id)}
                className={
                  "px-3 py-2 rounded-lg text-sm font-medium border transition-colors " +
                  (value.mode === m.id
                    ? "border-primary/60 bg-primary/10 text-foreground"
                    : "border-white/10 text-muted-foreground hover:text-foreground")
                }
              >
                {m.label}
              </button>
            ))}
          </div>

          {value.mode === "session" ? (
            <>
              <label className="flex flex-col gap-1.5">
                <span className="text-sm font-medium">Cookie</span>
                <input
                  className={inputClass}
                  placeholder="session=abc123; other=value"
                  value={value.cookie}
                  onChange={(e) => set("cookie", e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                />
                <span className="text-xs text-muted-foreground">
                  Copy the Cookie header from your browser's network tab while signed in.
                </span>
              </label>
              <label className="flex flex-col gap-1.5">
                <span className="text-sm font-medium">Bearer token</span>
                <input
                  className={inputClass}
                  placeholder="eyJhbGciOi…"
                  value={value.bearerToken}
                  onChange={(e) => set("bearerToken", e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                />
                <span className="text-xs text-muted-foreground">
                  Either field is enough — supply whichever your app uses.
                </span>
              </label>
            </>
          ) : (
            <>
              <label className="flex flex-col gap-1.5">
                <span className="text-sm font-medium">Sign-in page URL</span>
                <input
                  className={inputClass}
                  placeholder="https://your-app.com/login"
                  value={value.loginUrl}
                  onChange={(e) => set("loginUrl", e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                />
                <span className="text-xs text-muted-foreground">
                  Must be HTTPS. A sign-in this way can renew itself if the session expires
                  mid-scan, which a pasted cookie cannot.
                </span>
              </label>
              <label className="flex flex-col gap-1.5">
                <span className="text-sm font-medium">Username</span>
                <input
                  className={inputClass}
                  value={value.username}
                  onChange={(e) => set("username", e.target.value)}
                  autoComplete="off"
                />
              </label>
              <label className="flex flex-col gap-1.5">
                <span className="text-sm font-medium">Password</span>
                <input
                  type="password"
                  className={inputClass}
                  value={value.password}
                  onChange={(e) => set("password", e.target.value)}
                  autoComplete="new-password"
                />
              </label>
            </>
          )}

          {/* Second account — the whole basis of access-control testing */}
          <div className="flex flex-col gap-3 pt-1 border-t border-white/5">
            <label className="flex items-start gap-2.5 cursor-pointer pt-3">
              <input
                type="checkbox"
                checked={second.enabled}
                onChange={(e) => onSecondChange({ ...second, enabled: e.target.checked })}
                className="mt-0.5 w-4 h-4 accent-[var(--primary)]"
              />
              <span className="text-sm leading-relaxed">
                Also check whether one account can read another's data
                <span className="block text-xs text-muted-foreground mt-0.5">
                  Add a second account and we'll request the same records as both, and as a
                  visitor with no session. Broken access control is the most exploited flaw on
                  the web, and it can only be found by comparing two users.
                </span>
              </span>
            </label>

            {second.enabled ? (
              <div className="flex flex-col gap-3 pl-6">
                <label className="flex flex-col gap-1.5">
                  <span className="text-sm font-medium">Second account cookie</span>
                  <input
                    className={inputClass}
                    placeholder="session=def456"
                    value={second.cookie}
                    onChange={(e) => onSecondChange({ ...second, cookie: e.target.value })}
                    autoComplete="off"
                    spellCheck={false}
                  />
                </label>
                <label className="flex flex-col gap-1.5">
                  <span className="text-sm font-medium">Second account bearer token</span>
                  <input
                    className={inputClass}
                    value={second.bearerToken}
                    onChange={(e) => onSecondChange({ ...second, bearerToken: e.target.value })}
                    autoComplete="off"
                    spellCheck={false}
                  />
                </label>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  Use two ordinary accounts that own different data — not an administrator and a
                  user, which are <em>supposed</em> to see different things.
                </p>
              </div>
            ) : null}
          </div>

          <div className="flex items-start gap-2.5 p-3 rounded-lg bg-secondary/60 border border-white/10">
            <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <p className="text-xs text-muted-foreground leading-relaxed">
              Use a dedicated test account, not an administrator login. The scan avoids anything
              that looks like it deletes or cancels, but it is still signing in as this user and
              clicking around. Credentials are encrypted and deleted when the scan finishes.
            </p>
          </div>

          <label className="flex items-start gap-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={value.authorized}
              onChange={(e) => set("authorized", e.target.checked)}
              className="mt-0.5 w-4 h-4 accent-[var(--primary)]"
            />
            <span className="text-sm leading-relaxed">
              I'm authorised to sign in to this site and test it with these credentials.
            </span>
          </label>
        </div>
      ) : null}
    </div>
  );
}
