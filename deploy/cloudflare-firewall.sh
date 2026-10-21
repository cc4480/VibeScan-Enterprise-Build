#!/usr/bin/env bash
#
# Restrict inbound 80/443 to Cloudflare's published ranges.
#
# This is the other half of BEHIND_CLOUDFLARE=true. That setting makes the app
# trust CF-Connecting-IP to identify callers; this makes that trust warranted by
# ensuring requests cannot arrive any other way. With one and not the other, a
# client who learns the origin address can send whatever CF-Connecting-IP it
# likes and walk past every per-IP limit in the app.
#
# Re-runnable: Cloudflare's ranges change occasionally, so run it again after
# they do. It removes the rules it previously added before adding current ones.
#
#   sudo ./cloudflare-firewall.sh            # apply
#   sudo ./cloudflare-firewall.sh --dry-run  # print what it would do
#   sudo ./cloudflare-firewall.sh --force    # apply even if unrestricted 80/443 rules exist
#
# ufw applies rules in order. If a rule that admits 80 or 443 from anywhere is already
# present (for example from an earlier `ufw allow http`), it matches before the deny
# added here, and the restriction does nothing. The script therefore refuses to run in
# that case and lists the rules. --force overrides this; use it only if you understand
# why the rule is there. The check matches rules by port number; ufw rules created from
# an application profile name (such as "Nginx Full") are not detected, so look at
# `ufw status numbered` yourself before relying on this.
#
# SSH is never touched. Read the dry run before applying: locking yourself out
# of a remote server is tedious to undo and usually needs console access.

set -euo pipefail

DRY_RUN=0
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --force) FORCE=1 ;;
    *) echo "usage: $0 [--dry-run] [--force]" >&2; exit 2 ;;
  esac
done

if [[ $DRY_RUN -eq 0 && $EUID -ne 0 ]]; then
  echo "Run as root (sudo), or pass --dry-run." >&2
  exit 1
fi

command -v ufw >/dev/null || { echo "ufw is not installed." >&2; exit 1; }

COMMENT="cloudflare-origin"

run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "  would run: $*"
  else
    "$@"
  fi
}

echo "Fetching Cloudflare ranges…"
V4=$(curl -fsS --max-time 20 https://www.cloudflare.com/ips-v4)
V6=$(curl -fsS --max-time 20 https://www.cloudflare.com/ips-v6)

# A partial list would produce a firewall that blocks real traffic, so refuse to
# act on anything that does not look like the full published set.
count=$(printf '%s\n%s\n' "$V4" "$V6" | grep -c '/' || true)
if [[ "$count" -lt 20 ]]; then
  echo "Only $count ranges returned — expected at least 20. Refusing to apply." >&2
  exit 1
fi
echo "  $count ranges."

# Refuse while an unrestricted rule already admits 80 or 443 (see the header). Our own rules
# carry a source address, so they never match this; only rules a person added do.
echo "Checking for existing unrestricted rules on 80 and 443…"
if ! status="$(ufw status 2>/dev/null)"; then
  echo "Could not read ufw status. Run as root (sudo) so the check can run." >&2
  if [[ $FORCE -eq 0 ]]; then exit 1; fi
  status=""
fi
unscoped="$(printf '%s\n' "$status" | awk '$1 ~ /^(80|443)(\/tcp)?$/ && $0 ~ /ALLOW|LIMIT/ && $0 ~ /Anywhere/' || true)"
if [[ -n "$unscoped" ]]; then
  echo "Existing rules already admit 80 or 443 from anywhere. They match before the" >&2
  echo "Cloudflare-only rules below, so the restriction would not hold:" >&2
  printf '  %s\n' "$unscoped" >&2
  if [[ $FORCE -eq 0 ]]; then
    echo "Refusing to continue. Delete those rules (ufw status numbered, then ufw delete N)," >&2
    echo "or rerun with --force if they are intended." >&2
    exit 1
  fi
  echo "--force given: continuing with those rules still in place." >&2
fi

# Drop previously added rules so repeated runs converge rather than accumulate.
echo "Removing previous $COMMENT rules…"
while read -r num; do
  [[ -n "$num" ]] && run ufw --force delete "$num"
done < <(ufw status numbered 2>/dev/null | grep "$COMMENT" | sed -E 's/^\[ *([0-9]+)\].*/\1/' | sort -rn)

echo "Allowing Cloudflare to reach 80 and 443…"
while read -r cidr; do
  [[ -z "$cidr" ]] && continue
  run ufw allow proto tcp from "$cidr" to any port 80 comment "$COMMENT"
  run ufw allow proto tcp from "$cidr" to any port 443 comment "$COMMENT"
done < <(printf '%s\n%s\n' "$V4" "$V6")

# Deny everything else on those ports. ufw applies rules in order, so these sit
# after the allows above and only catch what they did not match.
echo "Denying 80 and 443 from everywhere else…"
run ufw deny proto tcp from any to any port 80 comment "$COMMENT"
run ufw deny proto tcp from any to any port 443 comment "$COMMENT"

if [[ $DRY_RUN -eq 1 ]]; then
  echo
  echo "Dry run only — nothing changed."
else
  echo
  echo "Applied. Confirm SSH still works from a second terminal before closing this one."
  ufw status verbose | head -20
fi
