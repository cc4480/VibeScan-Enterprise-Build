# etsy.com

- Requested: `https://www.etsy.com`
- HTTP 403, 1 inner page(s) fetched, 5.6s
- 4 findings, 1 above Info

> This scan was answered by a bot-protection interstitial. Findings read from that response are withheld, so this is a partial view — not a clean result.

### SPF Record Exceeds DNS Lookup Limit

**Low** · CWE-290 · Email Security

```
TXT record: v=spf1 ip4:66.3.159.0/24 ip4:192.147.0.0/24 ip4:173.46.67.72/29 ip4:192.147.1.0/24 ip4:38.106.64.0/24 ip4:38.76.1.0/24 ip4:38.76.2.0/24 ip4:162.220.28.32/27 ip4:162.220.28.64/28 ip4:208.74.204.0/22 ip4:46.19.168.0/23 include:servers.mcsv.net include:mail.zendesk.com include:amazonses.com include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com a:web.q4press.com include:cvent-planner.com include:mail.clinchtalent.com include:spf.redpoints.com -all
Estimated DNS lookups: ~10
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### DNSSEC Not Enabled

**Info** · CWE-350 · DNS Security

```
No DNSKEY records found for www.etsy.com or etsy.com (NOERROR (name exists)).
```

### Scan was intercepted by a bot-protection challenge

**Info** · Scan Coverage

```
DataDome challenge
```

