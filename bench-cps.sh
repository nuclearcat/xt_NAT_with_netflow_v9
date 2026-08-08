#!/bin/bash
#
# bench-cps.sh - ballpark session setup rate, and where it stops scaling.
#
# Drives unique (source ip, source port) pairs at the subscriber side of the
# test topology; each one is a new NAT session. Session rate is the delta of
# "Created NAT sessions" over the run. When creation starts failing, the
# per-reason counters say which limit was reached:
#
#   Failed sessions user limit     the per-user cap (4096/proto, hardcoded)
#   Failed sessions no free port   the NAT address ran out of ports
#   Failed sessions no memory      allocation failure
#
#   ./bench-cps.sh                     one run with the default pool
#   ./bench-cps.sh --duration 20
#   ./bench-cps.sh --senders 4         one generator process per core
#   ./bench-cps.sh --pool-sweep        1, 2, 4, 8, 16 NAT addresses
#   ./bench-cps.sh --gc-cost           what the GC costs at rest, vs table size
#   ./bench-cps.sh --netflow           with a collector attached, as deployed
#   ./bench-cps.sh --det 1008          deterministic RFC 7422 port blocks
#   ./bench-cps.sh --established 50    forwarding rate over established sessions,
#                                      not session setup - the metric a NAT
#                                      actually lives on
#   ./bench-cps.sh --pool 1 --duration 40
#                                      one NAT address, long enough to exhaust
#                                      its 64512 ports and show what happens
#
# READ THIS BEFORE QUOTING A NUMBER. In a VM, over veth, this measures a
# software path on a virtual CPU. The absolute figure is meaningless as a
# product claim. What it is good for is relative comparison - between commits,
# between pool sizes, between session counts - and for finding the point where
# the failure counters start moving, which is a property of the code and not
# of the NIC.
#
# The pool sweep is the interesting one: create_session_lock[] has one spinlock
# per NAT address, indexed by address, so a pool of N addresses serialises all
# session creation onto N locks no matter how many cores are pushing.
#

set -u

SRCDIR=$(cd "$(dirname "$0")" && pwd)
MODULE=${MODULE:-$SRCDIR/xt_CGNAT.ko}

. "$SRCDIR/testnet.sh"

DURATION=10
SENDERS=0            # 0 = one per online cpu, capped at 4
N_SRC_IPS=2000
SWEEP=0
GCCOST=0
NETFLOW=0
QUARANTINE=0
PER_IP=0
DET_PORTS=0
KEEP=0

if [ -t 1 ]; then
    C_G=$'\033[32m'; C_R=$'\033[31m'; C_Y=$'\033[33m'; C_B=$'\033[1m'; C_0=$'\033[0m'
else
    C_G=""; C_R=""; C_Y=""; C_B=""; C_0=""
fi
say()  { printf '%s\n' "$*"; }
info() { printf '     %s\n' "$*"; }
head_() { printf '\n%s== %s ==%s\n' "$C_B" "$*" "$C_0"; }
die()  { printf '%serror:%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

usage() { sed -n '2,/^$/s/^# \{0,1\}//p' "$0"; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        --duration) shift; DURATION=${1:-10} ;;
        --senders)  shift; SENDERS=${1:-0} ;;
        --src-ips)  shift; N_SRC_IPS=${1:-2000} ;;
        --pool-sweep) SWEEP=1 ;;
        --gc-cost)    GCCOST=1 ;;
        --netflow)    NETFLOW=1 ;;
        --pool)       shift; POOL_END=203.0.113.${1:-4} ;;
        --quarantine) QUARANTINE=1 ;;
        --established) shift; PER_IP=${1:-50} ;;
        --det)        shift; DET_PORTS=${1:-1008} ;;
        --keep)     KEEP=1 ;;
        -h|--help)  usage ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done

[ "$(id -u)" = 0 ] || die "must run as root"
[ -f "$MODULE" ] || die "module not found: $MODULE (run make first)"
if [ "${XT_NAT_TEST_FORCE:-0}" != 1 ]; then
    virt="none"; need systemd-detect-virt && virt=$(systemd-detect-virt 2>/dev/null || echo none)
    if [ "$virt" = none ] && ! grep -qi 'qemu\|kvm\|bochs' /sys/class/dmi/id/sys_vendor 2>/dev/null; then
        die "not a VM; this floods a live kernel. XT_NAT_TEST_FORCE=1 to override"
    fi
fi
xtables_libdir_setup || die "libxt_CGNAT.so not found - run 'make' first"

[ "$SENDERS" -gt 0 ] 2>/dev/null || {
    SENDERS=$(nproc 2>/dev/null || echo 2)
    [ "$SENDERS" -gt 4 ] && SENDERS=4
}

TMPD=$(mktemp -d)
GEN=$TMPD/cps-gen

int_from_ip() { local IFS=.; set -- $1; echo $(( ($1<<24)|($2<<16)|($3<<8)|$4 )); }
ip_from_int() { printf '%d.%d.%d.%d' $(( ($1>>24)&255 )) $(( ($1>>16)&255 )) $(( ($1>>8)&255 )) $(( $1&255 )); }
SRC_BASE=$(int_from_ip "$SUB_NET.10")

# Every measurement so far ran with no nf_dest, so netflow_sendmsg() walked an
# empty list: the global nfsend_lock and the record write were paid, the actual
# kernel_sendmsg() every 30 records was not. Nobody deploys it that way.
NF_DEST=127.0.0.1:2055
collector_start() {
    [ $NETFLOW = 1 ] || return 0
    cat >"$TMPD/collector.py" <<'EOF'
import socket, sys, signal
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
s.bind(('127.0.0.1', 2055))
s.settimeout(1)
n, out, run = 0, sys.argv[1], [True]
signal.signal(signal.SIGTERM, lambda *a: run.__setitem__(0, False))
while run[0]:
    try:
        s.recvfrom(65535); n += 1
    except socket.timeout:
        open(out, 'w').write(str(n))
open(out, 'w').write(str(n))
EOF
    python3 "$TMPD/collector.py" "$TMPD/nfcount" >/dev/null 2>&1 &
    COLLECTOR=$!
    sleep 0.5
}
collector_stop() {
    [ -n "${COLLECTOR:-}" ] || return 0
    kill "$COLLECTOR" 2>/dev/null; wait "$COLLECTOR" 2>/dev/null
    COLLECTOR=""
}

cleanup() {
    collector_stop
    [ $KEEP = 1 ] && { say "--keep: leaving topology up"; return; }
    rules_down; mod_down; net_down; rm -rf "$TMPD"
}
trap cleanup EXIT INT TERM

# counters worth reporting, in the order they tell the story
STATS=("Tried NAT sessions" "Created NAT sessions" "Active NAT sessions"
       "Failed sessions user limit" "Failed sessions no free port"
       "Failed sessions no memory" "Dropped no session" "DNAT dropped pkts"
       "Dropped truncated" "Dropped unwritable" "Active Users")

snapshot() {
    local k
    for k in "${STATS[@]}"; do printf '%s\n' "$(nat_stat "$k")"; done
}

# one measured run against whatever pool is currently configured
run_once() {
    local label=$1 before after i pid pids=() total_sent=0 out
    local dmac elapsed

    preload_deps
    rules_down; mod_down; net_down; sleep 0.2
    net_up
    # cap out of the way: we are measuring session rate, not the quota
    local extra="user_max_sessions=65535"
    [ $NETFLOW    = 1 ] && extra="$extra nf_dest=$NF_DEST"
    [ $QUARANTINE = 1 ] && extra="$extra port_quarantine=1"
        if [ "$DET_PORTS" != 0 ]; then
        # subscriber range must fit: pool addresses x (64512/ports) subscribers
        insmod "$MODULE" nat_pool=$POOL_START-$POOL_END:$SUB_CIDR:$DET_PORTS $extra \
            || { say "${C_R}insmod failed (deterministic)${C_0}"; return 1; }
    else
        mod_up $extra || { say "${C_R}insmod failed${C_0}"; return 1; }
    fi
    rules_up

    dmac=$(ip link show xn-s0 | awk '/link\/ether/{print $2}')
    [ -n "$dmac" ] || { say "${C_R}no mac for xn-s0${C_0}"; return 1; }

    before=$(snapshot)
    local t0 t1
    t0=$(date +%s.%N)

    local slice=$(( N_SRC_IPS / SENDERS )); [ $slice -lt 1 ] && slice=1
    for i in $(seq 0 $((SENDERS - 1))); do
        ip netns exec $NS_SUB "$GEN" xn-s1 "$dmac" \
            "$(ip_from_int $(( SRC_BASE + i * slice )))" "$slice" \
            "$INET_NET.2" "$DURATION" $PER_IP \
            > "$TMPD/gen.$i" 2>&1 &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid"; done

    t1=$(date +%s.%N)
    after=$(snapshot)
    elapsed=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')

    for i in $(seq 0 $((SENDERS - 1))); do
        out=$(awk '/^sent/{print $2}' "$TMPD/gen.$i" 2>/dev/null)
        total_sent=$((total_sent + ${out:-0}))
    done

    # deltas
    local d=() j=1 b a
    while [ $j -le ${#STATS[@]} ]; do
        b=$(echo "$before" | sed -n "${j}p"); a=$(echo "$after" | sed -n "${j}p")
        d+=($(( ${a:-0} - ${b:-0} )))
        j=$((j+1))
    done

    local created=${d[1]} tried=${d[0]}
    local cps pps
    cps=$(awk -v n="$created" -v t="$elapsed" 'BEGIN{printf "%.0f", (t>0)?n/t:0}')
    pps=$(awk -v n="$total_sent" -v t="$elapsed" 'BEGIN{printf "%.0f", (t>0)?n/t:0}')

    printf '%-12s %10s %10s %10s %10s %10s %10s\n' \
        "$label" "$pps" "$cps" "$tried" "${d[3]}" "${d[4]}" "${d[6]}"

    # In established mode the tuple space is bounded, so after the first pass
    # every packet hits a session that already exists: pps is forwarding rate,
    # and packets-per-session says how much of the run was actually forwarding.
    if [ "$PER_IP" != 0 ]; then
        awk -v p="$total_sent" -v c="${d[1]}" -v t="$elapsed" 'BEGIN{
            if (c > 0) printf "     forwarding: %d pps over %d established sessions (%.0f packets each)\n", p/t, c, p/c
        }'
    fi

    LAST_D=("${d[@]}")
    LAST_CPS=$cps
    return 0
}

# user+nice+system+irq+softirq, in USER_HZ
cpu_busy() { awk '/^cpu /{print $2+$3+$4+$7+$8}' /proc/stat; }

# Fill the table, stop, and see what the box still burns doing nothing. With no
# traffic the only work left is the cleanup timers, so this is the GC's cost as
# a function of how much it has to sweep.
gc_cost() {
    local fill=$1 window=10 b0 b1 act pct dmac gen="$TMPD/cps-gen"

    if [ "$fill" -gt 0 ]; then
        dmac=$(ip link show xn-s0 | awk '/link\/ether/{print $2}')
        local i pids=()
        for i in $(seq 0 $((SENDERS - 1))); do
            ip netns exec $NS_SUB "$gen" xn-s1 "$dmac" \
                "$(ip_from_int $(( SRC_BASE + i * 500 )))" 500 \
                "$INET_NET.3" "$fill" >/dev/null 2>&1 &
            pids+=($!)
        done
        for i in "${pids[@]}"; do wait "$i"; done
    fi

    sleep 2                       # let the last packets drain
    act=$(nat_stat "Active NAT sessions")
    b0=$(cpu_busy); sleep $window; b1=$(cpu_busy)
    pct=$(awk -v a="$b0" -v b="$b1" -v w="$window" 'BEGIN{printf "%.1f", (b-a)/100/w*100}')
    printf '%12s %14s\n' "${act:-0}" "${pct}%"
}

head_ "xt_CGNAT session setup rate"
info "kernel:    $(uname -r)"
info "senders:   $SENDERS x ${DURATION}s, $N_SRC_IPS source addresses"
info "module:    $MODULE"

if [ $NETFLOW = 1 ]; then
    info "netflow:   exporting to $NF_DEST"
    collector_start
fi

say ""
say "compiling generator"
gcc -O2 -o "$GEN" "$SRCDIR/cps-gen.c" || die "could not build cps-gen.c"

if [ $GCCOST = 1 ]; then
    head_ "GC cost at rest"
    say "Sessions are filled, then all traffic stops. Whatever CPU is still"
    say "being burned is the cleanup timers sweeping the table."
    say ""
    POOL_START=203.0.113.1
    POOL_END=203.0.113.16
    preload_deps; rules_down; mod_down; net_down; sleep 0.2
    net_up; mod_up user_max_sessions=65535 || die "insmod failed"; rules_up
    gcc -O2 -o "$TMPD/cps-gen" "$SRCDIR/cps-gen.c" || die "cps-gen build failed"
    printf '%12s %14s\n' "sessions" "cpu (1 core)"
    printf '%12s %14s\n' "--------" "------------"
    for f in 0 2 8 20; do gc_cost $f; done
    say ""
    say "The sweep visits every bucket every ~10s and writes to every session,"
    say "whether or not anything expired."
elif [ $SWEEP = 1 ]; then
    head_ "pool size sweep"
    say "create_session_lock[] is one spinlock per NAT address, so the pool size"
    say "bounds how much session creation can happen in parallel."
    say ""
    printf '%-12s %10s %10s %10s %10s %10s %10s\n' \
        "pool" "tx pps" "cps" "tried" "ulimit" "noport" "dropped"
    printf '%-12s %10s %10s %10s %10s %10s %10s\n' \
        "----" "------" "---" "-----" "------" "------" "-------"
    for n in 1 2 4 8 16; do
        POOL_START=203.0.113.1
        POOL_END=203.0.113.$n
        run_once "${n} addr" || break
    done
else
    printf '\n%-12s %10s %10s %10s %10s %10s %10s\n' \
        "pool" "tx pps" "cps" "tried" "ulimit" "noport" "dropped"
    printf '%-12s %10s %10s %10s %10s %10s %10s\n' \
        "----" "------" "---" "-----" "------" "------" "-------"
    run_once "$(echo "$POOL_END" | cut -d. -f4) addr"

    # A full cone NAT must never map two sessions to the same
    # (proto, nat ip, nat port): the outer table is keyed on exactly that, so a
    # duplicate means one subscriber's return traffic reaches another. The port
    # allocator is supposed to make this impossible, so check it rather than
    # assume it.
    head_ "port allocation invariant"
    local total dups
    total=$(awk '$1 ~ /^[0-9]+$/ && /->/ {n++} END{print n+0}' /proc/net/CGNAT/sessions 2>/dev/null)
    dups=$(awk '$1 ~ /^[0-9]+$/ && /->/ {print $1, $4}' /proc/net/CGNAT/sessions 2>/dev/null \
           | sort | uniq -d | wc -l)
    say "     sessions listed:            $total"
    say "     duplicate (proto,nat:port): $dups"
    if [ "${dups:-0}" -gt 0 ]; then
        say "     ${C_R}COLLISION: the same NAT port is mapped to more than one session${C_0}"
        awk '$1 ~ /^[0-9]+$/ && /->/ {print $1, $4}' /proc/net/CGNAT/sessions | sort | uniq -d | head -3 \
            | while read -r p np; do
                say "       proto $p $np used by:"
                awk -v p="$p" -v np="$np" '$1==p && $4==np {print "         " $0}' /proc/net/CGNAT/sessions | head -3
              done
    fi

    # Deterministic mode makes a promise: every session's NAT address and port
    # are computable from the subscriber address alone. Verify it against the
    # kernel's own session list rather than trusting the arithmetic.
    if [ "$DET_PORTS" != 0 ]; then
        head_ "deterministic mapping"
        awk -v base="$(int_from_ip "$SUB_NET.0")" -v ports="$DET_PORTS" \
            -v pool="$(int_from_ip "$POOL_START")" '
            function ip2i(s,  o) { split(s, o, "."); return o[1]*16777216 + o[2]*65536 + o[3]*256 + o[4] }
            $1 ~ /^[0-9]+$/ && /->/ {
                split($2, a, ":"); split($4, b, ":")
                idx = ip2i(a[1]) - base; per = int(64512 / ports)
                want_addr = pool + int(idx / per)
                lo = 1024 + (idx % per) * ports
                if (ip2i(b[1]) != want_addr || b[2] < lo || b[2] >= lo + ports) bad++
                n++
            }
            END { printf "     %d sessions checked, %d outside their computed block\n", n, bad+0 }
        ' /proc/net/CGNAT/sessions 2>/dev/null
    fi

    head_ "counters after the run"
    sed 's/^/     /' /proc/net/CGNAT/statistics 2>/dev/null

    head_ "reading it"
    if [ "${LAST_D[3]:-0}" -gt 0 ]; then
        say "  ${C_Y}per-user session limit reached${C_0} (${LAST_D[3]} refusals)."
        say "  4096 per protocol per user, hardcoded in check_user_limits()."
    fi
    if [ "${LAST_D[4]:-0}" -gt 0 ]; then
        say "  ${C_Y}NAT ports exhausted${C_0} (${LAST_D[4]} refusals)."
        say "  search_free_l4_port() walks up to 64512 lookups under the"
        say "  per-address spinlock before giving up - the expensive failure."
    fi
    if [ "${LAST_D[3]:-0}" = 0 ] && [ "${LAST_D[4]:-0}" = 0 ]; then
        say "  no session creation failures: the generator, not the NAT, was"
        say "  the limit. Raise --senders or --duration to push harder."
    fi
fi

if [ $NETFLOW = 1 ]; then
    collector_stop
    say ""
    say "NetFlow v9 packets received by the collector: $(cat "$TMPD/nfcount" 2>/dev/null || echo 0)"
    say "(zero would mean the export never happened and the comparison is void)"
fi

say ""
say "${C_Y}ballpark only${C_0}: veth in a VM. Use it to compare runs, not to quote a rate."
exit 0
