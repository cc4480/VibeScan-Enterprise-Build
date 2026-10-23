# github.com

- Requested: `https://github.com`
- HTTP 200, 31 inner page(s) fetched, 13.8s
- 11 findings, 5 above Info
- Risk score 23/100 — grade B

### Content-Security-Policy Missing on 1 Internal Route

**High** · CWE-79 · CVSS 7.2 · WSTG-CONF-12 · Security Header Inconsistency

```
Routes missing Content-Security-Policy:
  • /healthz (probed)
```

### X-Content-Type-Options Missing on 1 Internal Route

**Medium** · CWE-16 · CVSS 4.3 · WSTG-CONF-07 · Security Header Inconsistency

```
Routes missing X-Content-Type-Options:
  • /healthz (probed)
```

### Content-Security-Policy Allows Inline Styles (unsafe-inline in style-src)

**Low** · CWE-79 · CVSS 3.1 · WSTG-CONF-12 · Injection Defense

```
GET https://github.com/
Content-Security-Policy: default-src 'none'; base-uri 'self'; child-src github.githubassets.com github.com/assets-cdn/worker/ github.com/assets/ gist.github.com/assets-cdn/worker/; connect-src 'self' uploads.github.com www.githubstatus.com collector.github.com raw.githubusercontent.com api.github.com github-cloud.s3.amazonaws.com github-production-repository-file-5c1aeb.s3.amazonaws.com github-production-upload-manifest-file-7fdce7.s3.amazonaws.com github-production-user-asset-6210df.s3.amazonaws.com *.rel.tunnels.api.visualstudio.com wss://*.rel.tunnels.api.visualstudi
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://github.com/
Permissions-Policy: (header absent from response)
```

### Referrer-Policy Missing on 1 Internal Route

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Security Header Inconsistency

```
Routes missing Referrer-Policy:
  • /healthz (probed)
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### DNSSEC Not Enabled

**Info** · CWE-350 · DNS Security

```
No DNSKEY records found for github.com (NOERROR (name exists)).
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://github.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://github.com/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://github.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookie: _octo
```

