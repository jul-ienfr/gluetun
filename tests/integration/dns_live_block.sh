#!/bin/sh
# T049 - live DNS tier fallback measurement.
#
# Replays a filtered network on a test station: outbound DNS-over-TLS
# (TCP/853) and the well-known DoH endpoints are dropped, then the local
# resolver is queried repeatedly to measure the fallback latency. The
# acceptance criterion is a plain-tier fallback in <= 2 s at p95.
#
# This script performs live changes inside a throw-away station container and
# is therefore NOT part of the hot path: it never runs from the orchestrator
# and every rule is removed on exit.
#
# Requirements:
#   - a running Gluetun test container with iptables and nslookup available
#   - DNS_LADDER containing plain, e.g. "dot,doh,plain" or "dot,plain"
#
# Usage:
#   tests/integration/dns_live_block.sh                 # defaults below
#   CONTAINER=vpn-gluetun-test QUERIES=20 \
#     tests/integration/dns_live_block.sh
#
# The script exits 0 when p95 <= P95_BUDGET_MS, 1 otherwise.

set -eu

CONTAINER="${CONTAINER:-vpn-gluetun-test}"
QUERIES="${QUERIES:-12}"
HOSTNAME="${HOSTNAME:-example.com}"
P95_BUDGET_MS="${P95_BUDGET_MS:-2000}"
DOH_ADDRESSES="${DOH_ADDRESSES:-1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112}"

log() {
    printf '%s\n' "$*" >&2
}

usage() {
    sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
}

case "${1:-}" in
-h | --help)
    usage
    exit 0
    ;;
"") ;;
*)
    log "unknown argument: $1"
    usage
    exit 2
    ;;
esac

if ! command -v docker >/dev/null 2>&1; then
    log "docker is required to run this live test"
    exit 1
fi

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
    log "container not found: $CONTAINER"
    exit 1
fi

exec_in() {
    docker exec "$CONTAINER" sh -c "$1"
}

DOT_RULE="iptables -I OUTPUT -p tcp --dport 853 -j DROP"
FAMILY_RULES=""
for address in $DOH_ADDRESSES; do
    case "$address" in
    *:*) FAMILY_RULES="$FAMILY_RULES ip6tables -I OUTPUT -p tcp -d $address --dport 443 -j DROP;" ;;
    *) FAMILY_RULES="$FAMILY_RULES iptables -I OUTPUT -p tcp -d $address --dport 443 -j DROP;" ;;
    esac
done

cleanup() {
    log "removing filter rules"
    exec_in "iptables -D OUTPUT -p tcp --dport 853 -j DROP" >/dev/null 2>&1 || true
    for address in $DOH_ADDRESSES; do
        case "$address" in
        *:*) exec_in "ip6tables -D OUTPUT -p tcp -d $address --dport 443 -j DROP" >/dev/null 2>&1 || true ;;
        *) exec_in "iptables -D OUTPUT -p tcp -d $address --dport 443 -j DROP" >/dev/null 2>&1 || true ;;
        esac
    done
}
trap cleanup EXIT INT TERM

log "blocking TCP/853 and known DoH endpoints inside $CONTAINER"
exec_in "$DOT_RULE"
exec_in "$FAMILY_RULES"

log "querying $HOSTNAME $QUERIES times through the local resolver"
measurements=""
i=1
while [ "$i" -le "$QUERIES" ]; do
    started=$(date +%s%N)
    if ! exec_in "nslookup $HOSTNAME 127.0.0.1" >/dev/null 2>&1; then
        log "query $i failed: resolver did not answer"
        exit 1
    fi
    finished=$(date +%s%N)
    elapsed_ms=$(( (finished - started) / 1000000 ))
    measurements="$measurements$elapsed_ms
"
    i=$((i + 1))
done

p95=$(printf '%s' "$measurements" | sort -n | awk '
    { values[NR] = $1 }
    END {
        if (NR == 0) { print 0; exit }
        index = int((NR * 95 + 99) / 100)
        if (index < 1) { index = 1 }
        if (index > NR) { index = NR }
        print values[index]
    }
')

minimum=$(printf '%s' "$measurements" | sort -n | head -n 1)
maximum=$(printf '%s' "$measurements" | sort -n | tail -n 1)

log "latencies (ms): $(printf '%s' "$measurements" | tr '\n' ' ')"
log "min=$minimum p95=$p95 max=$maximum budget=$P95_BUDGET_MS"

if [ "$p95" -le "$P95_BUDGET_MS" ]; then
    log "PASS: plain fallback within budget"
    exit 0
fi

log "FAIL: p95 $p95 ms exceeds budget $P95_BUDGET_MS ms"
exit 1
