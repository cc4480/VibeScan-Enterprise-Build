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
#   - artifacts/vuln-fixture: this repo is a vulnerability scanner, and this fixture
#     holds deliberately planted fake credentials by design
#   - this script and its allowlist
# __fixtures__ directories ARE scanned. Everything that legitimately contains a fake
# credential (the scanner's own detection tests, and any fixture that trips a pattern) is
# listed one file at a time, with a reason, in scripts/scan-secrets.allowlist. A new file
# that trips the scan is therefore a conscious decision: remove the secret, or add the
# file there with a comment.

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
  # A connection string with a password inline. The password class excludes $ { } < > * so the
  # placeholder forms (${POSTGRES_PASSWORD}, <password>, ***) do not match; the password must be
  # 6+ characters and cannot be empty.
  'database-url-password|postgres(ql)?://[^:/[:space:]@]+:[^[:space:]@$<>{}*/]{6,}@'
  # DeepSeek and OpenAI keys are sk- followed by a long alphanumeric run. The leading boundary
  # stops a match inside a longer identifier such as task-... or my-sk-....
  'sk-api-key|(^|[^A-Za-z0-9_-])sk-[A-Za-z0-9]{32,}'
  # Resend keys: re_ followed by 24+ alphanumerics. Same boundary reasoning as sk-.
  'resend-key|(^|[^A-Za-z0-9_])re_[A-Za-z0-9]{24,}'
  # ENCRYPTION_KEY or any *_SECRET assigned a 32+ character value. Allows an optional quote
  # before and after the value, but not a $ or < (shell and template placeholders).
  'secret-assignment|(ENCRYPTION_KEY|[A-Z0-9_]*_SECRET)[^[:alnum:]$<{[:space:]]{0,3}[[:space:]]*[:=][[:space:]]*[^[:alnum:]$<{[:space:]]{0,2}[A-Za-z0-9+/=_-]{32,}'
)

# Lines a pattern must NOT report even though its regex matched (grep -viE, case-insensitive),
# keyed by pattern name. Used for placeholder forms that are shaped like a real value, such as
# postgres://user:password@host in an .env template. Keep these narrow: a real secret must not
# be able to hide behind a word here.
declare -A PLACEHOLDER_FILTER=(
  ['database-url-password']='://[^:/[:space:]]+:(password|pass|placeholder|changeme|example|secret|redacted|your[-_a-z]*|x{4,})@'
)

# Repo-relative paths that are never scanned (extended regex, matched with grep -E).
EXCLUDE_RE='(^|/)(node_modules|\.git)/|(^|/)(pnpm-lock\.yaml|package-lock\.json|yarn\.lock)$|^artifacts/vuln-fixture/|^scripts/scan-secrets\.(sh|allowlist)$'

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
  local base="$1" list entry name regex filter
  list="$(mktemp)"
  cat >"$list"
  for entry in "${PATTERNS[@]}"; do
    name="${entry%%|*}"
    regex="${entry#*|}"
    filter="${PLACEHOLDER_FILTER[$name]:-}"
    # -I skips binary files; -H keeps the filename even for a single file.
    (cd "$base" && xargs -0 -r grep -IHnE -e "$regex" <"$list" 2>/dev/null || true) |
      { if [[ -n "$filter" ]]; then grep -viE -e "$filter" || true; else cat; fi; } |
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

  # Newer patterns, same construction: each fake is assembled from pieces so this file does not
  # itself match. The placeholder file must stay clean: it is the form the templates use.
  fake_db="postgres://app:""Zq8vLm2nRt@db.internal/app"
  fake_sk="sk-""AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
  fake_enc="ENCRYPTION_KEY=""abcdefghijklmnopqrstuvwxyz012345"
  printf 'DATABASE_URL=%s\n' "$fake_db" >"$dir/leak-db.txt"
  printf 'deepseek = %s\n' "$fake_sk" >"$dir/leak-sk.txt"
  printf '%s\n' "$fake_enc" >"$dir/leak-secret.txt"
  printf '%s\n%s\n%s\n' \
    'DATABASE_URL=postgresql://user:password@localhost:5432/vibescan' \
    'DATABASE_URL=postgresql://app:${POSTGRES_PASSWORD}@db:5432/app' \
    'ENCRYPTION_KEY=${ENCRYPTION_KEY:?must be set}' >"$dir/placeholder.txt"

  out="$(cd "$dir" && printf '%s\0' leak-aws.txt leak-pem.txt clean.txt leak-db.txt leak-sk.txt leak-secret.txt placeholder.txt | scan_files "$dir")"

  grep -q '^leak-aws.txt:1: aws-access-key-id$' <<<"$out" || { echo "self-test FAILED: AWS key not detected" >&2; rc=1; }
  grep -q '^leak-pem.txt:1: private-key$' <<<"$out" || { echo "self-test FAILED: private key header not detected" >&2; rc=1; }
  grep -q '^leak-db.txt:1: database-url-password$' <<<"$out" || { echo "self-test FAILED: database URL password not detected" >&2; rc=1; }
  grep -q '^leak-sk.txt:1: sk-api-key$' <<<"$out" || { echo "self-test FAILED: sk- key not detected" >&2; rc=1; }
  grep -q '^leak-secret.txt:1: secret-assignment$' <<<"$out" || { echo "self-test FAILED: ENCRYPTION_KEY assignment not detected" >&2; rc=1; }
  if grep -q '^clean.txt:' <<<"$out"; then echo "self-test FAILED: clean file was flagged" >&2; rc=1; fi
  if grep -q '^placeholder.txt:' <<<"$out"; then echo "self-test FAILED: placeholder forms were flagged" >&2; rc=1; fi
  if grep -qF "$fake_aws" <<<"$out"; then echo "self-test FAILED: report leaked the matched text" >&2; rc=1; fi
  if grep -qE 'Zq8vLm2nRt|AbCdEfGhIj|abcdefghijklmnop' <<<"$out"; then echo "self-test FAILED: report leaked a new fake's text" >&2; rc=1; fi

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
