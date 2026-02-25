#!/usr/bin/env bash
set -euo pipefail

API_BASE="https://frenzynets.com/api/frenzynet"
ENROLL_TOKEN=""
NODE_NAME=""
NODE_HOST=""
REGION=""
SERVER_POOL=""
TIER=""
STATUS="active"

usage() {
  cat <<USAGE
Usage:
  install-frenzynet-node.sh --enroll-token TOKEN [options]

Options:
  --enroll-token TOKEN   One-time enroll token from FrenzyNet Admin
  --name NAME            Server node name (default: hostname)
  --host HOST            Host or DNS label (default: hostname -f)
  --region REGION        Optional override
  --server-pool POOL     Optional override
  --tier TIER            Optional override (standard|premium)
  --status STATUS        Initial status (default: active)
  --api-base URL         Control API base URL
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --enroll-token) ENROLL_TOKEN="${2:-}"; shift 2 ;;
    --name) NODE_NAME="${2:-}"; shift 2 ;;
    --host) NODE_HOST="${2:-}"; shift 2 ;;
    --region) REGION="${2:-}"; shift 2 ;;
    --server-pool) SERVER_POOL="${2:-}"; shift 2 ;;
    --tier) TIER="${2:-}"; shift 2 ;;
    --status) STATUS="${2:-}"; shift 2 ;;
    --api-base) API_BASE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1"; usage; exit 1 ;;
  esac
done

if [[ -z "$ENROLL_TOKEN" ]]; then
  echo "Missing --enroll-token"; usage; exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
  echo "Run with sudo/root."; exit 1
fi

install_pkgs() {
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y curl jq ca-certificates wireguard-tools
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl jq ca-certificates wireguard-tools || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl jq ca-certificates wireguard-tools || true
  fi
}
install_pkgs

NODE_NAME="${NODE_NAME:-$(hostname)}"
NODE_HOST="${NODE_HOST:-$(hostname -f 2>/dev/null || hostname)}"
PUBLIC_IP="$(curl -fsSL https://api.ipify.org || true)"

payload="$(jq -n \
  --arg t "$ENROLL_TOKEN" \
  --arg n "$NODE_NAME" \
  --arg h "$NODE_HOST" \
  --arg ip "$PUBLIC_IP" \
  --arg r "$REGION" \
  --arg p "$SERVER_POOL" \
  --arg tier "$TIER" \
  --arg st "$STATUS" \
  '{enrollToken:$t,name:$n,host:$h,publicIp:$ip,region:$r,serverPool:$p,tier:$tier,status:$st,agentVersion:"node-bootstrap-1"}')"

enroll_resp="$(curl -fsSL -X POST "$API_BASE/api/server/enroll" -H 'Content-Type: application/json' --data "$payload")"
AGENT_TOKEN="$(echo "$enroll_resp" | jq -r '.agentToken // empty')"
if [[ -z "$AGENT_TOKEN" ]]; then
  echo "Enroll failed: $enroll_resp"
  exit 1
fi

mkdir -p /opt/frenzynet-node
chmod 700 /opt/frenzynet-node

cat > /etc/frenzynet-node-agent.env <<ENV
FNET_API_BASE=${API_BASE}
FNET_SERVER_NAME=${NODE_NAME}
FNET_SERVER_HOST=${NODE_HOST}
FNET_AGENT_TOKEN=${AGENT_TOKEN}
FNET_AGENT_VERSION=node-agent-1
ENV
chmod 600 /etc/frenzynet-node-agent.env

cat > /opt/frenzynet-node/heartbeat.sh <<'HB'
#!/usr/bin/env bash
set -euo pipefail
source /etc/frenzynet-node-agent.env
PUBLIC_IP="$(curl -fsSL https://api.ipify.org || true)"
payload="$(jq -n --arg status "active" --arg ip "$PUBLIC_IP" --arg v "${FNET_AGENT_VERSION}" --arg notes "auto-heartbeat" '{status:$status,publicIp:$ip,agentVersion:$v,notes:$notes}')"
curl -fsSL -X POST "${FNET_API_BASE}/api/server/heartbeat" -H "Authorization: Bearer ${FNET_AGENT_TOKEN}" -H 'Content-Type: application/json' --data "$payload" >/dev/null
HB
chmod 700 /opt/frenzynet-node/heartbeat.sh

cat > /etc/systemd/system/frenzynet-node-heartbeat.service <<'UNIT'
[Unit]
Description=FrenzyNet Node Heartbeat
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/frenzynet-node/heartbeat.sh
User=root
UNIT

cat > /etc/systemd/system/frenzynet-node-heartbeat.timer <<'UNIT'
[Unit]
Description=FrenzyNet Node Heartbeat Timer

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
Unit=frenzynet-node-heartbeat.service

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now frenzynet-node-heartbeat.timer
systemctl start frenzynet-node-heartbeat.service || true

echo "Bootstrap complete for ${NODE_NAME}."
