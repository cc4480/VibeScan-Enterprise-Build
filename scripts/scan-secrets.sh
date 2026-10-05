#!/usr/bin/env bash
# Lightweight secret scan for CI: greps the checked-out tree for a short list of
# high-confidence credential patterns and exits non-zero on any match.
#
#   bash scripts/scan-secrets.sh              scan the tree (what CI runs)
#   bash scripts/scan-secrets.sh --self-test  prove the scanner still detects a planted key
#
# Deliberately small: no third-party action, no network, no history scan. It is a
# tripwire for the obvious mistake (a real key pasted into a file), not a
# replacement for GitHub's own secret scanning / push protection.
#
# The report prints file:line and the pattern NAME only, never the matched text,
# so a real secret that trips this scan is not copied into the CI log.
#
# What is not scanned:
#   - node_modules, .git, lockfiles
#   - __fixtures__ directories and artifacts/vuln-fixture: this repo is a
#     vulnerability scanner, and these hold deliberately planted fake credentials
#   - this script and its allowlist
# Everything else that legitimately contains a fake credential (the scanner's own
# detection tests, for example) is listed one file at a time, with a reason, in
# scripts/scan-secrets.allowlist. A new file that trips the scan is therefore a
# conscious decision: remove the secret, or add the file there with a comment.

set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOWLIST="$ROOT/scripts/scan-secrets.allowlist"

# name|extended regex. Names appear in the report; keep them free of '|'.
PATTERNS=(
  # Covers RSA/EC/DSA/OPENSSH/PGP/ENCRYPTED keys and the bare PKCS#8 header.
  'private-key|-----BEGIN [A-Z ]*PRIVATE KEY'
  'aws-access-key-id|AKIA[0-9A-Z]{16}'
  'stripe-live-key|[sr]k_live_[0-9a-zA-Z]{20,}'
  'github-token|gh[pousr]_[0-9A-Za-z]{36,}'
  'github-fine-grained-token|github_pat_[0-9A-Za-z_]{22,}'
  'slack-token|xox[baprs]-[0-9A-Za-z-]{10,}'
)

# Repo-relative paths that are never scanned (extended regex, matched with grep -E).
EXCLUDE_RE='(^|/)(node_modules|\.git)/|(^|/)(pnpm-lock\.yaml|package-lock\.json|yarn\.lock)$|(^|/)__fixtures__/|^artifacts/vuln-fixture/|^scripts/scan-secrets\.(sh|allowlist)$'

# NUL-separated, repo-relative file list on stdout. Tracked files when this is a
# git checkout (CI), otherwise a plain walk.
list_files() {
  if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -C "$ROOT" ls-files -z
  else
    (cd "$ROOT" && find . -type f \
      -not -path './.git/*' -not -path '*/node_modules/*' -not -path '*/dist/*' \
      -print0 | sed -z 's|^\./||')
  fi | { grep -zvE "$EXCLUDE_RE" || true; }
}

# Reads a NUL-separated file list on stdin (paths relative to $1) and prints one
# "path:line: pattern-name" per hit. Never prints the matching line itself.
scan_files() {
  local base="$1" list entry name regex
  list="$(mktemp)"
  cat >"$list"
  for entry in "${PATTERNS[@]}"; do
    name="${entry%%|*}"
    regex="${entry#*|}"
    # -I skips binary files; -H keeps the filename even for a single file.
    (cd "$base" && xargs -0 -r grep -IHnE -e "$regex" <"$list" 2>/dev/null || true) |
      cut -d: -f1,2 | sed "s|\$|: $name|"
  done
  rm -f "$list"
}

# Drops hits whose file is listed in the allowlist. Entries are exact repo-relative
# paths, one per line; blank lines and '#' comments are ignored.
apply_allowlist() {
  if [[ -f "$ALLOWLIST" ]]; then
    local allowed
    allowed="$(grep -vE '^[[:space:]]*(#|$)' "$ALLOWLIST" | sed 's/[[:space:]]*$//' || true)"
    if [[ -n "$allowed" ]]; then
      # awk: -F: splits on the first colon-delimited field, which is the path.
      awk -F: 'NR==FNR { allow[$0]=1; next } !($1 in allow)' <(printf '%s\n' "$allowed") -
      return
    fi
  fi
  cat
}

self_test() {
  local dir fake_aws fake_pem out rc=0
  dir="$(mktemp -d)"

  # Built from pieces so this file never contains a complete match itself.
  fake_aws="AKIA""ABCDEFGHIJKLMNOP"
  fake_pem="-----BEGIN ""RSA PRIVATE KEY-----"
  printf 'aws_access_key_id = %s\n' "$fake_aws" >"$dir/leak-aws.txt"
  printf '%s\nMIIB\n' "$fake_pem" >"$dir/leak-pem.txt"
  printf 'nothing to see here\nAKIA is a prefix, not a key\n' >"$dir/clean.txt"

  out="$(cd "$dir" && printf '%s\0' leak-aws.txt leak-pem.txt clean.txt | scan_files "$dir")"

  grep -q '^leak-aws.txt:1: aws-access-key-id$' <<<"$out" || { echo "self-test FAILED: AWS key not detected" >&2; rc=1; }
  grep -q '^leak-pem.txt:1: private-key$' <<<"$out" || { echo "self-test FAILED: private key header not detected" >&2; rc=1; }
  if grep -q '^clean.txt:' <<<"$out"; then echo "self-test FAILED: clean file was flagged" >&2; rc=1; fi
  if grep -qF "$fake_aws" <<<"$out"; then echo "self-test FAILED: report leaked the matched text" >&2; rc=1; fi

  # The allowlist must suppress exactly the file it names and nothing else.
  local saved="$ALLOWLIST"
  ALLOWLIST="$dir/allowlist"
  printf '# test\nleak-aws.txt\n' >"$ALLOWLIST"
  out="$(printf '%s\n' "$(cd "$dir" && printf '%s\0' leak-aws.txt leak-pem.txt | scan_files "$dir")" | apply_allowlist)"
  ALLOWLIST="$saved"
  if grep -q '^leak-aws.txt:' <<<"$out"; then echo "self-test FAILED: allowlisted file still reported" >&2; rc=1; fi
  grep -q '^leak-pem.txt:' <<<"$out" || { echo "self-test FAILED: allowlist suppressed a file it does not name" >&2; rc=1; }

  rm -rf "$dir"
  if [[ $rc -eq 0 ]]; then echo "scan-secrets self-test passed"; fi
  return $rc
}

main() {
  local hits
  hits="$(list_files | scan_files "$ROOT" | apply_allowlist | sort -u)"
  if [[ -n "$hits" ]]; then
    echo "Possible secrets found (pattern name shown, matched text withheld):" >&2
    echo "$hits" >&2
    echo >&2
    echo "Remove the secret and rotate it. If it is a deliberate fake, add the file to" >&2
    echo "scripts/scan-secrets.allowlist with a comment saying why." >&2
    exit 1
  fi
  echo "scan-secrets: no secrets found"
}

case "${1:-}" in
  --self-test) self_test ;;
  "") main ;;
  *) echo "usage: $0 [--self-test]" >&2; exit 2 ;;
esac
