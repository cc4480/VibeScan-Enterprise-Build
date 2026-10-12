/**
 * Plain-language names for the categories listed on the report cover under
 * "Also detected:". A category holds several checks, so each label has to
 * describe all of them, not just the first one that was written.
 */
export const NEW_CATEGORY_LABELS: Record<string, string> = {
  "Email Security":                  "email spoofing risks",
  "Source Code Exposure":            "exposed source code",
  "Credential Exposure":             "exposed credentials",
  "Data Exposure":                   "exposed data files",
  "Exposed Secrets / Credentials":   "hardcoded secrets in JavaScript",
  "CORS Misconfiguration":           "CORS bypass issues",
  "Unvalidated Redirects":           "open redirect vulnerabilities",
  "HTTP Security":                   "HTTP security issues (response headers, cookies, HTTP methods)",
  "Supply Chain Security":           "supply chain weaknesses",
  "Session Management":              "JWT / session token weaknesses",
  "Brute Force Protection":          "missing rate limiting",
  "DNS Security":                    "DNS security issues",
  "Information Disclosure":          "information disclosure (server version, robots.txt, error pages, exposed files)",
  "Transport Security":              "transport security issues (TLS versions, certificate, HTTPS redirect, HSTS)",
  "UI Security":                     "UI security gaps (clickjacking protection)",
  "Security Header Inconsistency":   "header inconsistencies across pages",
  "Outdated Software / Known CVE":   "outdated software with known CVEs",
};
