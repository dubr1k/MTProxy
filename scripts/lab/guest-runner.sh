#!/usr/bin/env bash
# shellcheck disable=SC2317 # scenario functions are dispatched by name through case_run.
set -Eeuo pipefail

MODE=${1:-smoke}
EXPECTED_ARCHIVE_SHA=${2:-}
ROOT=/tmp/mtproxy-source
FIXTURE=/tmp/proxyctl-host
PROXY=proxy.lab.test
PANEL=panel.lab.test
ROUTE=/etc/nginx/stream.d/routes.conf
RESULTS_FAILED=0
BASELINE=/tmp/lab-baseline.sha256
declare -A CASE_STATUS=()

emit() {
  local name=$1 status=$2 started=$3 message=${4:-}
  local elapsed
  elapsed=$(python3 - "$started" <<'PY'
import sys,time
print(f"{time.time()-float(sys.argv[1]):.3f}")
PY
)
  message=${message//$'\t'/ }
  message=${message//$'\n'/ }
  message=${message:0:4000}
  printf 'LAB_RESULT\t%s\t%s\t%s\t%s\n' "$name" "$status" "$elapsed" "$message"
  [[ $status == passed ]] || RESULTS_FAILED=1
}

case_run() {
  local name=$1 function=$2 started log rc message prerequisite
  shift 2
  started=$(python3 -c 'import time; print(time.time())')
  for prerequisite in "$@"; do
    if [[ ${CASE_STATUS[$prerequisite]:-missing} != passed ]]; then
      CASE_STATUS[$name]=skipped
      emit "$name" skipped "$started" "prerequisite failed: $prerequisite"
      return 0
    fi
  done
  log=$(mktemp)
  set +e
  ( set -Eeuo pipefail; "$function" ) >"$log" 2>&1
  rc=$?
  set -e
  if ((rc == 0)); then
    CASE_STATUS[$name]=passed
    emit "$name" passed "$started"
  else
    CASE_STATUS[$name]=failed
    message=$(tr '\n' ' ' <"$log")
    emit "$name" failed "$started" "$message"
  fi
  rm -f "$log"
}

add_hosts() {
  if ! grep -q "$PROXY" /etc/hosts; then
    printf '10.0.2.15 %s %s\n' "$PROXY" "$PANEL" >> /etc/hosts
  fi
}

make_fixture() {
  rm -rf "$FIXTURE"
  mkdir -p "$FIXTURE/etc/nginx/stream.d" "$FIXTURE/etc/nginx/sites-enabled" \
    "$FIXTURE/usr/local/x-ui/bin" "$FIXTURE/etc/letsencrypt/live/$PROXY" \
    "$FIXTURE/etc/letsencrypt/live/$PANEL" "$FIXTURE/var/lib/lab-status"
  cat > "$FIXTURE/etc/nginx/nginx.conf" <<'EOF'
stream { include /etc/nginx/stream.d/*.conf; }
EOF
  cat > "$FIXTURE$ROUTE" <<'EOF'
map $ssl_preread_server_name $shared_backend {
    old-xray.lab.test 127.0.0.1:9443;
    default 127.0.0.1:8443;
}
server { listen 443; proxy_pass $shared_backend; ssl_preread on; }
EOF
  cat > "$FIXTURE/usr/local/x-ui/bin/config.json" <<'EOF'
{"inbounds":[{"tag":"xray-reality","protocol":"vless","listen":"127.0.0.1","port":9443,"streamSettings":{"security":"reality","realitySettings":{"serverNames":["old-xray.lab.test"]}}}],"outbounds":[{"tag":"warp"}]}
EOF
  printf 'active\n' > "$FIXTURE/var/lib/lab-status/nginx"
  printf 'active\n' > "$FIXTURE/var/lib/lab-status/xray"
  printf 'active\n' > "$FIXTURE/var/lib/lab-status/3x-ui"
  printf 'active\n' > "$FIXTURE/var/lib/lab-status/warp"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$PROXY" \
    -addext "subjectAltName=DNS:$PROXY,DNS:$PANEL" \
    -keyout /tmp/lab.key -out /tmp/lab.crt >/dev/null 2>&1
  for domain in "$PROXY" "$PANEL"; do
    cp /tmp/lab.crt "$FIXTURE/etc/letsencrypt/live/$domain/fullchain.pem"
    cp /tmp/lab.key "$FIXTURE/etc/letsencrypt/live/$domain/privkey.pem"
  done
  find "$FIXTURE" -type f -print0 | sort -z | xargs -0 sha256sum > /tmp/fixture.before
}

proxy_args() {
  printf '%s\n' --proxy-domain "$PROXY" --panel-domain "$PANEL" --email lab@example.invalid \
    --route-file "$ROUTE" --users owner,phone --protocol-probe /usr/local/bin/lab-probe \
    --source-dir "$ROOT"
}

archive_integrity() {
  [[ -n $EXPECTED_ARCHIVE_SHA ]]
  [[ $(sha256sum /tmp/mtproxy-source.tar | cut -d' ' -f1) == "$EXPECTED_ARCHIVE_SHA" ]]
  [[ $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true) == "" ]] # archive is intentionally metadata-free
  test -f "$ROOT/scripts/proxyctl.py"
}

audit_fixture() {
  python3 "$ROOT/scripts/proxyctl.py" --root "$FIXTURE" audit \
    --proxy-domain "$PROXY" --panel-domain "$PANEL" --json >/tmp/audit.json
  python3 - <<'PY'
import json
r=json.load(open('/tmp/audit.json'))
assert r['nginx']['sni_map_count'] == 1
assert r['xray']['installed'] and r['xray']['outbound_tags'] == ['warp']
assert all(d['dns_matches_host'] and d['tls_certificate_present'] for d in r['domains'])
PY
}

plan_fixture() {
  mapfile -t args < <(proxy_args)
  python3 "$ROOT/scripts/proxyctl.py" --root "$FIXTURE" plan "${args[@]}" --json >/tmp/plan.json
  python3 -m json.tool /tmp/plan.json >/dev/null
}

coexist_fixture() {
  find "$FIXTURE" -type f -print0 | sort -z | xargs -0 sha256sum > /tmp/fixture.after
  cmp /tmp/fixture.before /tmp/fixture.after
  grep -qx active "$FIXTURE"/var/lib/lab-status/{nginx,xray,3x-ui,warp}
}

dns_tls_fixture() {
  python3 - <<'PY'
import json
r=json.load(open('/tmp/audit.json'))
assert {d['domain'] for d in r['domains']} == {'proxy.lab.test','panel.lab.test'}
assert all(d['a_records'] == ['10.0.2.15'] for d in r['domains'])
assert all(not d['unhandled_aaaa'] for d in r['domains'])
assert all(d['tls_certificate_present'] for d in r['domains'])
PY
}

secrets_scan() {
  ! grep -ERi '(panel-bootstrap-password|telemt-api-token)[=:][^[:space:]]+|tg://proxy\?.*secret=' \
    /tmp/audit.json /tmp/plan.json 2>/dev/null
}

setup_full_host() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq nginx-full libnginx-mod-stream docker.io docker-compose-v2 certbot openssl socat jq >/dev/null
  add_hosts
  mkdir -p /etc/nginx/stream.d /usr/local/x-ui/bin /var/lib/lab-status
  cat > /etc/nginx/nginx.conf <<'EOF'
load_module modules/ngx_stream_module.so;
user www-data;
pid /run/nginx.pid;
events { worker_connections 256; }
stream { include /etc/nginx/stream.d/*.conf; }
http { include /etc/nginx/sites-enabled/*; }
EOF
  cat > "$ROUTE" <<'EOF'
map $ssl_preread_server_name $shared_backend {
    old-xray.lab.test 127.0.0.1:9443;
    default 127.0.0.1:9443;
}
server { listen 443; proxy_pass $shared_backend; ssl_preread on; }
EOF
  cat > /usr/local/x-ui/bin/config.json <<'EOF'
{"inbounds":[{"tag":"xray-reality","protocol":"vless","listen":"127.0.0.1","port":9443,"streamSettings":{"security":"reality","realitySettings":{"serverNames":["old-xray.lab.test"]}}}],"outbounds":[{"tag":"warp"}]}
EOF
  cat > /etc/systemd/system/lab-xray.service <<'EOF'
[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:9443,bind=127.0.0.1,reuseaddr,fork EXEC:/bin/cat
EOF
  cat > /etc/systemd/system/lab-warp.service <<'EOF'
[Service]
ExecStart=/usr/bin/sleep infinity
EOF
  cat > /etc/systemd/system/lab-3x-ui.service <<'EOF'
[Service]
ExecStart=/usr/bin/sleep infinity
EOF
  systemctl daemon-reload
  systemctl enable --now lab-xray lab-warp lab-3x-ui docker nginx >/dev/null
  cat > /usr/local/bin/lab-probe <<'EOF'
#!/bin/sh
set -eu
test "$1" = --domain
test "$3" = --secrets-file
test -s "$4"
EOF
  chmod 755 /usr/local/bin/lab-probe
  cat > /usr/local/bin/certbot <<'EOF'
#!/bin/bash
set -eu
name= domains=()
while (($#)); do
  case $1 in --cert-name) name=$2; shift 2;; -d) domains+=("$2"); shift 2;; *) shift;; esac
done
test -n "$name"
dir=/etc/letsencrypt/live/$name
mkdir -p "$dir"
test "${#domains[@]}" -eq 2
san="DNS:${domains[0]},DNS:${domains[1]}"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$name" -addext "subjectAltName=$san" -keyout "$dir/privkey.pem" -out "$dir/fullchain.pem" >/dev/null 2>&1
for domain in "${domains[@]}"; do
  target=/etc/letsencrypt/live/$domain
  mkdir -p "$target"
  cp "$dir/fullchain.pem" "$target/fullchain.pem"
  cp "$dir/privkey.pem" "$target/privkey.pem"
done
EOF
  chmod 755 /usr/local/bin/certbot
  sha256sum "$ROUTE" /usr/local/x-ui/bin/config.json > "$BASELINE"
  systemctl is-active nginx lab-xray lab-warp lab-3x-ui > /tmp/status.before
}

full_environment_preflight() {
  local started log script
  started=$(python3 -c 'import time; print(time.time())')
  log=$(mktemp)
  script="$(declare -p PROXY PANEL ROUTE BASELINE); $(declare -f add_hosts setup_full_host); setup_full_host"
  if bash -Eeuo pipefail -c "$script" >"$log" 2>&1; then
    emit environment-preflight passed "$started"
    rm -f "$log"
    return 0
  fi
  emit environment-preflight failed "$started" "$(tail -n 5 "$log" | tr '\n' ' ')"
  sed 's/^/environment-preflight: /' "$log" >&2
  rm -f "$log"
  return 1
}

runtime_cmd() {
  mapfile -t args < <(proxy_args)
  python3 "$ROOT/scripts/proxyctl.py" "$1" "${args[@]}"
}

full_audit() { python3 "$ROOT/scripts/proxyctl.py" audit --proxy-domain "$PROXY" --panel-domain "$PANEL" --json >/tmp/audit.json; }
full_plan() { runtime_cmd plan >/tmp/plan.json; }
full_install() {
  test ! -e /var/lib/proxy-control/runtime.json
  test ! -e /var/lib/proxy-control/ownership.json
  test ! -e /opt/mtproxy-shared443
  runtime_cmd install >/tmp/install.out
  systemctl is-active docker nginx >/dev/null
  test "$(stat -c %a /var/lib/proxy-control/runtime.json)" = 600
  jq -e '.status == "active" and (.owned_packages == [])' /var/lib/proxy-control/runtime.json >/dev/null
  test "$(stat -c %a /var/lib/proxy-control/ownership.json)" = 600
}
full_repair() { python3 "$ROOT/scripts/proxyctl.py" repair; test "$(jq -r .status /var/lib/proxy-control/runtime.json)" = active; }
full_idempotence() {
  local before after
  before=$(sha256sum /var/lib/proxy-control/runtime.json | cut -d' ' -f1)
  runtime_cmd install >/tmp/idempotent.out
  after=$(sha256sum /var/lib/proxy-control/runtime.json | cut -d' ' -f1)
  [[ $before == "$after" ]]
}
full_uninstall() {
  python3 "$ROOT/scripts/proxyctl.py" uninstall
  python3 "$ROOT/scripts/proxyctl.py" uninstall
  test ! -e /var/lib/proxy-control/runtime.json
  test ! -e /var/lib/proxy-control/ownership.json
  sha256sum -c "$BASELINE" >/dev/null
  systemctl is-active nginx lab-xray lab-warp lab-3x-ui > /tmp/status.after
  cmp /tmp/status.before /tmp/status.after
  dpkg-query -W nginx-full docker.io docker-compose-v2 certbot >/dev/null
  rm -rf /opt/mtproxy-shared443
}

interrupt_install_recovery() {
  test ! -e /var/lib/proxy-control/runtime.json
  test ! -e /var/lib/proxy-control/ownership.json
  test ! -e /opt/mtproxy-shared443
  mapfile -t args < <(proxy_args)
  set +e
  PROXYCTL_TEST_CRASH_AFTER_PHASE=project_rendered \
    python3 "$ROOT/scripts/proxyctl.py" install "${args[@]}" >/tmp/interrupted-install.log 2>&1
  local interrupted_rc=$?
  set -e
  test "$interrupted_rc" -eq 137
  test -f /var/lib/proxy-control/runtime.json
  test "$(jq -r .phase /var/lib/proxy-control/runtime.json)" = project_rendered
  runtime_cmd install >/tmp/recovered-install.out
  test "$(jq -r .status /var/lib/proxy-control/runtime.json)" = active
  test -f /var/lib/proxy-control/ownership.json
}

interrupt_uninstall_recovery() {
  test "$(jq -r .status /var/lib/proxy-control/runtime.json)" = active
  test -f /var/lib/proxy-control/ownership.json
  set +e
  PROXYCTL_TEST_CRASH_AFTER_PHASE=compose_down \
    python3 "$ROOT/scripts/proxyctl.py" uninstall >/tmp/interrupted-uninstall.log 2>&1
  local interrupted_rc=$?
  set -e
  test "$interrupted_rc" -eq 137
  test "$(jq -r .phase /var/lib/proxy-control/runtime.json)" = compose_down
  python3 "$ROOT/scripts/proxyctl.py" uninstall
  test ! -e /var/lib/proxy-control/runtime.json
  test ! -e /var/lib/proxy-control/ownership.json
}

docker_build_check() {
  docker image inspect mtproxy-panel >/dev/null 2>&1 || docker image ls --format '{{.Repository}}' | grep -qx mtproxy-panel
}

full_coexist() {
  sha256sum -c "$BASELINE" >/dev/null
  systemctl is-active nginx lab-xray lab-warp lab-3x-ui >/dev/null
  ss -lnt | grep -q ':443 '
  ss -lnt | grep -q ':9443 '
}

full_dns_tls() {
  full_audit
  dns_tls_fixture
}

full_secrets_scan() {
  if grep -ERi 'tg://proxy\?.*secret=|telemt-api-token[=:][^[:space:]]+|panel-bootstrap-password[=:][^[:space:]]+' \
    /tmp/*.out /tmp/*.log /tmp/audit.json /tmp/plan.json 2>/dev/null; then
    return 1
  fi
  test "$(stat -c %a /opt/mtproxy-shared443/secrets 2>/dev/null || echo 700)" = 700
}

if [[ ${GUEST_RUNNER_LIB_ONLY:-0} == 1 ]]; then
  return 0 2>/dev/null || exit 0
fi

add_hosts
make_fixture
if [[ $MODE == smoke ]]; then
  case_run archive-integrity archive_integrity
  case_run audit audit_fixture
  case_run plan plan_fixture
  case_run coexistence coexist_fixture
  case_run dns-tls-preflight dns_tls_fixture
  case_run secrets-scan secrets_scan
elif [[ $MODE == full ]]; then
  if ! full_environment_preflight; then
    exit "$RESULTS_FAILED"
  fi
  CASE_STATUS[environment-preflight]=passed
  case_run audit full_audit environment-preflight
  case_run plan full_plan audit
  case_run install full_install plan
  case_run docker-build docker_build_check install
  case_run repair full_repair install
  case_run idempotence full_idempotence repair
  case_run secrets-scan full_secrets_scan idempotence
  case_run uninstall full_uninstall idempotence
  case_run interrupted-install-recovery interrupt_install_recovery uninstall
  case_run interrupted-uninstall-recovery interrupt_uninstall_recovery interrupted-install-recovery
  case_run coexistence full_coexist interrupted-uninstall-recovery
  case_run dns-tls-preflight full_dns_tls audit
else
  printf 'unknown mode: %s\n' "$MODE" >&2
  exit 2
fi
exit "$RESULTS_FAILED"
