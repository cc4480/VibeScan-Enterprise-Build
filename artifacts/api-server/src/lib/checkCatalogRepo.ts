/**
 * The checks a repository scan runs (a GitHub or Git repository given as the target, or read alongside a website scan).
 * Each group is a step the scan records under the name below (see repoScan.ts), and each check is one finding site.
 *
 * Names that carry a variable part (a table, a bucket, a package) are listed by their fixed start, and the needle is
 * a literal that proves the check exists in the file that raises it. checkCatalog.test.ts verifies the needles.
 *
 * Categories here only colour the row on the site; they are kept to the ones the palette knows. The finding itself
 * keeps its own category in the report.
 */
import { test, type CatalogTest } from "./checkCatalogTypes";

export const CATALOG_REPO: CatalogTest[] = [
  test("repository secrets", "Credential Exposure", "repoScan.ts", [
    ["varies", "Credential found in the repository's files (secret patterns)", "(in source repository)"],
  ]),
  test("Supabase migrations (RLS and policies)", "Broken Access Control", "repoCheckSupabase.ts", [
    ["low", "Supabase Function Runs With Its Owner's Rights and No Pinned search_path"],
    ["medium", "Supabase View Bypasses Row Level Security (no security_invoker)"],
    ["medium", "Supabase Storage Policy Lets Anyone List and Read", "Supabase Storage Policy Lets Anyone List and Read"],
    ["high", "Supabase Tables Created Without Row Level Security"],
    ["low", "Supabase Policy Lets Anyone Insert", 'Supabase Policy Lets Anyone Insert "'],
    ["info", "Supabase Policy Opens", "(for a test or demo)"],
    ["high", "Supabase Policy Lets Anyone Update, Delete or Read and Write", "p.command[0]!.toUpperCase()"],
    ["varies", "Supabase Policy Lets Anyone Read", 'Supabase Policy Lets Anyone Read "'],
    ["medium", "Supabase Policy Lets Every Signed-In User Reach All Rows", "Supabase Policy Lets Every Signed-In User Reach All Rows of"],
    ["high", "Supabase Access Decided From user_metadata", undefined, "repoCheckSupabaseExtra.ts", "Broken Access Control"],
    ["medium", "Supabase SECURITY DEFINER Function Callable by Anyone", undefined, "repoCheckSupabaseExtra.ts", "Broken Access Control"],
    ["medium", "Supabase Table Holds a Sensitive-Looking Column", undefined, "repoCheckSupabaseExtra.ts", "Data Exposure"],
    ["medium", "Supabase Storage Bucket Named Like Private Files Is Public", undefined, "repoCheckSupabaseExtra.ts", "Cloud Storage Misconfiguration"],
    ["medium", "Supabase Anonymous Sign-Ins Are Enabled", undefined, "repoCheckSupabaseExtra.ts", "Broken Access Control"],
    ["low", "Supabase Email Sign-Ups Are Not Confirmed", undefined, "repoCheckSupabaseExtra.ts", "Broken Access Control"],
  ]),
  test("CI and configuration", "Security Misconfiguration", "repoCheckCi.ts", [
    ["high", "GitHub Actions Workflow Runs Pull-Request Code With Repository Secrets", undefined, undefined, "Injection"],
    ["high", "GitHub Actions Shell Step Interpolates Attacker-Controlled Text", undefined, undefined, "Injection"],
    ["medium", "GitHub Actions Workflow Requests write-all Permissions"],
    ["medium", "GitHub Actions Step Prints a Secret", undefined, undefined, "Exposed Secrets / Credentials"],
    ["high", "Dockerfile Bakes a Credential Into the Image", undefined, undefined, "Exposed Secrets / Credentials"],
    ["high", "Webhook Edge Function Accepts Unsigned Requests", undefined, undefined, "Broken Access Control"],
    ["medium", "Supabase Edge Functions Configured Without JWT Verification", undefined, undefined, "Broken Access Control"],
    ["critical", "Firestore or Cloud Storage Rules Let Anyone Write", "Rules Let Anyone Write", "repoCheckInfra.ts", "Broken Access Control"],
    ["varies", "Firestore or Cloud Storage Rules Let Anyone Read", "Rules Let Anyone Read", "repoCheckInfra.ts", "Broken Access Control"],
    ["critical", "Realtime Database Rules Let Anyone Write", undefined, "repoCheckInfra.ts", "Broken Access Control"],
    ["high", "Realtime Database Rules Let Anyone Read", undefined, "repoCheckInfra.ts", "Broken Access Control"],
    ["medium", "Dockerfile Pipes a Download Into a Shell", undefined, "repoCheckInfra.ts", "Supply Chain Security"],
    ["low", "Container Runs as Root", undefined, "repoCheckInfra.ts", "Security Misconfiguration"],
    ["low", "Dockerfile Base Image Is Not Pinned", undefined, "repoCheckInfra.ts", "Supply Chain Security"],
    ["high", "Compose Service Runs Privileged", undefined, "repoCheckInfra.ts", "Security Misconfiguration"],
    ["varies", "Compose Service Mounts the Docker Socket", undefined, "repoCheckInfra.ts", "Security Misconfiguration"],
    ["varies", "Compose Publishes a Database Port to Every Network Interface", undefined, "repoCheckInfra.ts", "Security Misconfiguration"],
    ["low", "GitHub Actions Uses Third-Party Actions Pinned to a Mutable Tag", undefined, "repoCheckInfra.ts", "Supply Chain Security"],
    ["info", "GitHub Actions Passes Every Secret to a Called Workflow", undefined, "repoCheckInfra.ts", "Security Misconfiguration"],
  ]),
  test("dangerous code patterns", "Injection", "repoCheckCode.ts", [
    ["high", "Secret Exposed Through a Client-Side Environment Prefix", undefined, undefined, "Exposed Secrets / Credentials"],
    ["high", "eval or new Function on Request Data"],
    ["high", "SQL Built From Request Data by String Interpolation"],
    ["medium", "CORS Allows Any Origin With Credentials", undefined, undefined, "CORS Misconfiguration"],
    ["medium", "TLS Certificate Verification Disabled", undefined, undefined, "Transport Security"],
    ["medium", "AI Provider Key Used Directly in Browser Code", undefined, undefined, "AI Feature Security"],
    ["high", "Hardcoded JWT Signing Secret", undefined, "repoCodeRules.ts", "Exposed Secrets / Credentials"],
    ["high", "JWT Verification Accepts the none Algorithm", undefined, "repoCodeRules.ts", "Broken Access Control"],
    ["medium", "Raw SQL Built by String Concatenation or Interpolation", undefined, "repoCodeRules.ts"],
    ["high", "Operating-System Command Built From Request Data", undefined, "repoCodeRules.ts"],
    ["medium", "File Path Taken From Request Data", undefined, "repoCodeRules.ts"],
    ["medium", "Server Fetches a URL Taken From Request Data", undefined, "repoCodeRules.ts", "Server-Side Request Forgery"],
    ["medium", "Redirect to an Address Taken From Request Data", undefined, "repoCodeRules.ts", "Unvalidated Redirects"],
    ["medium", "Predictable Random Number Used for a Secret", undefined, "repoCodeRules.ts", "Session Management"],
    ["medium", "Password Hashed With MD5 or SHA-1", undefined, "repoCodeRules.ts", "Security Misconfiguration"],
    ["low", "Session Cookie Without HttpOnly or Secure", undefined, "repoCodeRules.ts", "Session Management"],
    ["medium", "dangerouslySetInnerHTML With Unsanitised Content", undefined, "repoCodeRules.ts"],
    ["medium", "API Route Changes Data With No Sign-In Check Visible", undefined, "repoCodeRules.ts", "Broken Access Control"],
    ["medium", "Environment File Committed to the Repository", undefined, "repoCodeRules.ts", "Exposed Secrets / Credentials"],
  ]),
  test("dependency vulnerabilities (OSV)", "Vulnerable Components", "manifestSca.ts", [
    ["critical", "Malicious package:", "Malicious package: "],
    ["varies", "Vulnerable dependency:", "Vulnerable dependency: "],
  ]),
];
