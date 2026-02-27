#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-https://api.frenzynets.com/api/telewatch}"
SITE_BASE="${SITE_BASE:-https://frenzynets.com}"
ADMIN_USER="${ADMIN_USER:-}"
ADMIN_PASS="${ADMIN_PASS:-}"
ADMIN_CODE="${ADMIN_CODE:-}"

if [[ -z "$ADMIN_USER" || -z "$ADMIN_PASS" || -z "$ADMIN_CODE" ]]; then
  echo "FAIL: missing credentials. Set ADMIN_USER, ADMIN_PASS, ADMIN_CODE env vars."
  exit 2
fi

PASS=0
FAIL=0
WARN=0

say_pass() { echo "PASS: $*"; PASS=$((PASS+1)); }
say_fail() { echo "FAIL: $*"; FAIL=$((FAIL+1)); }
say_warn() { echo "WARN: $*"; WARN=$((WARN+1)); }

post_json() {
  local path="$1"
  local payload="$2"
  local out="$3"
  curl -sS -m 25 -o "$out" -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -X POST "${API_BASE}${path}" \
    --data "$payload"
}

get_json() {
  local url="$1"
  local out="$2"
  curl -sS -m 25 -o "$out" -w "%{http_code}" "$url"
}

json_field() {
  local file="$1"
  local expr="$2"
  node -e "const fs=require('fs');let j={};try{j=JSON.parse(fs.readFileSync(process.argv[1],'utf8')||'{}')}catch(e){}; const v=(function(){return ${expr};})(); process.stdout.write(v==null?'':String(v));" "$file"
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# 1) Public settings health
body="$tmpdir/public-settings.json"
code="$(get_json "${API_BASE}/public-settings" "$body" || true)"
if [[ "$code" == "200" ]]; then
  ok="$(json_field "$body" "j.ok")"
  if [[ "$ok" == "true" ]]; then
    say_pass "public-settings reachable"
  else
    say_fail "public-settings returned 200 but ok!=true"
  fi
else
  say_fail "public-settings HTTP $code"
fi

# 2) Admin login
body="$tmpdir/login.json"
payload="{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}"
code="$(post_json "/api/watch/admin/login" "$payload" "$body" || true)"
if [[ "$code" != "200" ]]; then
  say_fail "admin login HTTP $code"
  echo "RESULT: FAIL (cannot continue without admin login)"
  exit 1
fi
admin_token="$(json_field "$body" "j.adminToken")"
if [[ -z "$admin_token" ]]; then
  say_fail "admin login missing token"
  echo "RESULT: FAIL (cannot continue without admin token)"
  exit 1
fi
say_pass "admin login"

# 3) Admin list
a_body="$tmpdir/admin-list.json"
code="$(post_json "/api/watch/admin/list" "{\"adminToken\":\"${admin_token}\"}" "$a_body" || true)"
if [[ "$code" == "200" ]]; then
  say_pass "admin list"
else
  say_fail "admin list HTTP $code"
fi

# 4) Admin settings get
s_body="$tmpdir/admin-settings.json"
code="$(post_json "/api/watch/admin/settings" "{\"adminToken\":\"${admin_token}\",\"action\":\"get\"}" "$s_body" || true)"
if [[ "$code" == "200" ]]; then
  say_pass "admin settings get"
else
  say_fail "admin settings get HTTP $code"
fi

# 5) Create temp room lifecycle
room_code="SMK$(date +%H%M%S)"
c_body="$tmpdir/create-room.json"
create_payload="{\"adminToken\":\"${admin_token}\",\"roomCode\":\"${room_code}\",\"displayName\":\"SmokeHost\",\"title\":\"Smoke Test\",\"accessMode\":\"public\",\"mediaMode\":\"webrtc\"}"
code="$(post_json "/api/watch/create" "$create_payload" "$c_body" || true)"
participant_token=""
created_room=""
if [[ "$code" == "200" ]]; then
  created_room="$(json_field "$c_body" "j.roomCode")"
  participant_token="$(json_field "$c_body" "j.participantToken")"
  if [[ -n "$created_room" && -n "$participant_token" ]]; then
    say_pass "create room (${created_room})"
  else
    say_fail "create room missing roomCode/participantToken"
  fi
elif [[ "$code" == "409" ]]; then
  err="$(json_field "$c_body" "j.error")"
  say_warn "create room conflict (${err}) - skipping room lifecycle checks"
else
  say_fail "create room HTTP $code"
fi

if [[ -n "$created_room" && -n "$participant_token" ]]; then
  ctl_body="$tmpdir/control.json"
  ctl_payload="{\"roomCode\":\"${created_room}\",\"participantToken\":\"${participant_token}\",\"action\":\"set_title\",\"title\":\"Smoke Updated\"}"
  code="$(post_json "/api/watch/control" "$ctl_payload" "$ctl_body" || true)"
  if [[ "$code" == "200" ]]; then
    say_pass "control set_title"
  else
    say_fail "control set_title HTTP $code"
  fi

  del_body="$tmpdir/delete.json"
  del_payload="{\"roomCode\":\"${created_room}\",\"adminToken\":\"${admin_token}\",\"adminCode\":\"${ADMIN_CODE}\"}"
  code="$(post_json "/api/watch/delete" "$del_payload" "$del_body" || true)"
  if [[ "$code" == "200" ]]; then
    say_pass "delete room"
  else
    say_fail "delete room HTTP $code"
  fi
fi

# 6) Admin page cache header
h_body="$tmpdir/admin-head.txt"
code="$(curl -sS -m 20 -I -o "$h_body" -w "%{http_code}" "${SITE_BASE}/telewatch/admin/" || true)"
if [[ "$code" == "200" ]]; then
  if grep -qi "cache-control: .*no-store" "$h_body"; then
    say_pass "admin page no-cache header"
  else
    say_warn "admin page no-cache header not present"
  fi
else
  say_warn "admin page HEAD HTTP $code"
fi

# 7) Logout
l_body="$tmpdir/logout.json"
code="$(post_json "/api/watch/admin/logout" "{\"adminToken\":\"${admin_token}\"}" "$l_body" || true)"
if [[ "$code" == "200" ]]; then
  say_pass "admin logout"
else
  say_warn "admin logout HTTP $code"
fi

echo ""
echo "Summary: PASS=${PASS} WARN=${WARN} FAIL=${FAIL}"
if [[ "$FAIL" -gt 0 ]]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: PASS"
