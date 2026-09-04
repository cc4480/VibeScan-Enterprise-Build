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
#   sudo ./cloudflare-firewall.sh          # apply
#   sudo ./cloudflare-firewall.sh --dry-run  # print what it would do
#
# SSH is never touched. Read the dry run before applying: locking yourself out
# of a remote server is tedious to undo and usually needs console access.

set -euo pipefail

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

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
