#!/usr/bin/env bash
set -euo pipefail

REMOTE="origin"
BRANCH=""
MAX_ATTEMPTS=6
BASE_DELAY=2
MAX_DELAY=30
ENABLE_RESOLVER_FALLBACK=0
DRY_RUN=0

FALLBACK_MARKER_START="# FN_DEPLOY_DNS_FALLBACK_START"
FALLBACK_MARKER_END="# FN_DEPLOY_DNS_FALLBACK_END"
FALLBACK_APPLIED=0

usage() {
  cat <<'EOF'
Usage: scripts/deploy-github.sh [options]

Options:
  --remote <name>              Git remote (default: origin)
  --branch <name>              Branch to push (default: current branch)
  --max-attempts <n>           Retry attempts for push (default: 6)
  --base-delay <seconds>       Initial retry delay (default: 2)
  --max-delay <seconds>        Maximum retry delay (default: 30)
  --resolver-fallback          On DNS failures, add temporary /etc/hosts fallback for github.com
  --dry-run                    Run push in dry-run mode
  -h, --help                   Show this help

Examples:
  scripts/deploy-github.sh --branch main
  scripts/deploy-github.sh --branch main --resolver-fallback
EOF
}

log() {
  printf '[deploy] %s\n' "$*"
}

require_int() {
  local label="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    log "Invalid integer for ${label}: ${value}"
    exit 2
  fi
}

resolve_host() {
  local host="$1"
  if command -v getent >/dev/null 2>&1; then
    getent ahosts "$host" 2>/dev/null | awk 'NR==1 { print $1; exit }'
    return 0
  fi
  if command -v dig >/dev/null 2>&1; then
    dig +short "$host" A 2>/dev/null | awk 'NR==1 { print $1; exit }'
    return 0
  fi
  return 1
}

resolve_host_via_public_dns() {
  local host="$1"
  if ! command -v dig >/dev/null 2>&1; then
    return 1
  fi
  local ip=""
  ip="$(dig +short @"1.1.1.1" "$host" A 2>/dev/null | awk 'NR==1 { print $1; exit }')"
  if [[ -z "$ip" ]]; then
    ip="$(dig +short @"8.8.8.8" "$host" A 2>/dev/null | awk 'NR==1 { print $1; exit }')"
  fi
  [[ -n "$ip" ]] && printf '%s' "$ip"
}

has_dns_block() {
  grep -q "$FALLBACK_MARKER_START" /etc/hosts 2>/dev/null
}

clear_dns_fallback() {
  [[ "$FALLBACK_APPLIED" -eq 1 ]] || return 0
  if [[ ! -w /etc/hosts ]]; then
    if command -v sudo >/dev/null 2>&1; then
      sudo bash -lc "awk '/$FALLBACK_MARKER_START/{skip=1;next}/$FALLBACK_MARKER_END/{skip=0;next}!skip{print}' /etc/hosts > /tmp/hosts.deploy.$$ && cp /tmp/hosts.deploy.$$ /etc/hosts && rm -f /tmp/hosts.deploy.$$"
    else
      log "Could not clear /etc/hosts fallback (no write permission)."
    fi
  else
    awk '/'"$FALLBACK_MARKER_START"'/{skip=1;next}/'"$FALLBACK_MARKER_END"'/{skip=0;next}!skip{print}' /etc/hosts > /tmp/hosts.deploy.$$
    cp /tmp/hosts.deploy.$$ /etc/hosts
    rm -f /tmp/hosts.deploy.$$
  fi
  FALLBACK_APPLIED=0
  log "Removed temporary DNS fallback block."
}

apply_dns_fallback() {
  if [[ "$ENABLE_RESOLVER_FALLBACK" -ne 1 ]]; then
    return 1
  fi
  if has_dns_block; then
    FALLBACK_APPLIED=1
    return 0
  fi
  local github_ip=""
  local api_ip=""
  github_ip="$(resolve_host_via_public_dns github.com || true)"
  api_ip="$(resolve_host_via_public_dns api.github.com || true)"
  if [[ -z "$github_ip" || -z "$api_ip" ]]; then
    log "Resolver fallback requested, but failed to resolve GitHub via public DNS."
    return 1
  fi

  local block
  block="$(cat <<EOF
$FALLBACK_MARKER_START
$github_ip github.com
$api_ip api.github.com
$FALLBACK_MARKER_END
EOF
)"

  if [[ -w /etc/hosts ]]; then
    printf '\n%s\n' "$block" >> /etc/hosts
  elif command -v sudo >/dev/null 2>&1; then
    printf '\n%s\n' "$block" | sudo tee -a /etc/hosts >/dev/null
  else
    log "Resolver fallback needs root or sudo to modify /etc/hosts."
    return 1
  fi
  FALLBACK_APPLIED=1
  log "Applied temporary /etc/hosts fallback for github.com -> $github_ip."
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --remote)
      REMOTE="${2:-}"
      shift 2
      ;;
    --branch)
      BRANCH="${2:-}"
      shift 2
      ;;
    --max-attempts)
      MAX_ATTEMPTS="${2:-}"
      shift 2
      ;;
    --base-delay)
      BASE_DELAY="${2:-}"
      shift 2
      ;;
    --max-delay)
      MAX_DELAY="${2:-}"
      shift 2
      ;;
    --resolver-fallback)
      ENABLE_RESOLVER_FALLBACK=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      log "Unknown option: $1"
      usage
      exit 2
      ;;
  esac
done

require_int "max-attempts" "$MAX_ATTEMPTS"
require_int "base-delay" "$BASE_DELAY"
require_int "max-delay" "$MAX_DELAY"

if [[ -z "$BRANCH" ]]; then
  BRANCH="$(git rev-parse --abbrev-ref HEAD)"
fi

trap clear_dns_fallback EXIT

log "Remote: $REMOTE"
log "Branch: $BRANCH"
log "Retry policy: attempts=$MAX_ATTEMPTS base_delay=${BASE_DELAY}s max_delay=${MAX_DELAY}s"
if [[ "$ENABLE_RESOLVER_FALLBACK" -eq 1 ]]; then
  log "Resolver fallback: enabled"
fi

if ! git remote get-url "$REMOTE" >/dev/null 2>&1; then
  log "Remote not found: $REMOTE"
  exit 2
fi

delay="$BASE_DELAY"
attempt=1
while [[ "$attempt" -le "$MAX_ATTEMPTS" ]]; do
  log "Push attempt ${attempt}/${MAX_ATTEMPTS}..."
  set +e
  if [[ "$DRY_RUN" -eq 1 ]]; then
    OUTPUT="$(git push --dry-run "$REMOTE" "$BRANCH" 2>&1)"
  else
    OUTPUT="$(git push "$REMOTE" "$BRANCH" 2>&1)"
  fi
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    log "Push completed."
    exit 0
  fi

  log "Push failed: ${OUTPUT}"
  if grep -qi "Could not resolve host" <<<"$OUTPUT"; then
    log "Detected DNS resolution failure."
    apply_dns_fallback || true
  fi

  if [[ "$attempt" -ge "$MAX_ATTEMPTS" ]]; then
    break
  fi
  log "Retrying in ${delay}s..."
  sleep "$delay"
  delay=$(( delay * 2 ))
  if [[ "$delay" -gt "$MAX_DELAY" ]]; then
    delay="$MAX_DELAY"
  fi
  attempt=$(( attempt + 1 ))
done

log "Push failed after ${MAX_ATTEMPTS} attempts."
exit 1
