#!/bin/bash
#
# qemu-tests.sh - functional and regression tests for the xt_NAT module.
#
# Runs a NAT topology entirely inside one machine using network namespaces:
#
#      netns xtnat-sub                root netns (DUT)              netns xtnat-inet
#   10.0.0.2 --- xn-s1 <=> xn-s0 10.0.0.1 | 198.51.100.1 xn-i0 <=> xn-i1 --- 198.51.100.2
#                                    xt_NAT, pool 203.0.113.1-4
#
# Meant to be run as root in a throwaway VM. It insmods an out-of-tree NAT
# module and rewrites the root namespace's iptables rules, so it refuses to
# run on anything that does not look virtualised unless you insist.
#
# The point is not performance - virtio numbers mean nothing. The point is to
# run this code under a debug kernel:
#
#   KASAN, PROVE_LOCKING, PROVE_RCU, DEBUG_ATOMIC_SLEEP, DEBUG_OBJECTS_TIMERS,
#   SLUB_DEBUG, DEBUG_KMEMLEAK, DEBUG_LIST
#
# Every test is followed by a scan of dmesg for splats, which is where most of
# the value is. A test that "passes" on a kernel without KASAN has proved much
# less than the same test on one with it.
#
# Build the module and libxt_NAT.so against the kernel you are going to boot,
# then run this inside it. Note that it sets the FORWARD policy to ACCEPT and
# does not put it back.
#
# Usage:
#   ./qemu-tests.sh                 run the standard set
#   ./qemu-tests.sh --soak          also run the session-aging test (~2 min)
#   ./qemu-tests.sh --keep          leave the topology up afterwards
#   ./qemu-tests.sh --vng /path/to/linux
#                                   (re)launch itself under virtme-ng
#
# Environment:
#   MODULE=/path/to/xt_NAT.ko       default ./xt_NAT.ko
#   XT_NAT_TEST_FORCE=1             allow running on non-virtualised hosts
#

set -u

SRCDIR=$(cd "$(dirname "$0")" && pwd)
MODULE=${MODULE:-$SRCDIR/xt_NAT.ko}

NS_SUB=xtnat-sub
NS_INET=xtnat-inet
SUB_NET=10.0.0
INET_NET=198.51.100
POOL_NET=203.0.113.0/24
POOL_START=203.0.113.1
POOL_END=203.0.113.4
POOL_PREFIX=203.0.113.

SOAK=0
KEEP=0
VNG_KDIR=""

TMPD=$(mktemp -d)
PASSED=0
FAILED=0
SKIPPED=0
FAILED_NAMES=()

# ---------------------------------------------------------------- output ---

if [ -t 1 ]; then
    C_G=$'\033[32m'; C_R=$'\033[31m'; C_Y=$'\033[33m'; C_B=$'\033[1m'; C_0=$'\033[0m'
else
    C_G=""; C_R=""; C_Y=""; C_B=""; C_0=""
fi

say()  { printf '%s\n' "$*"; }
info() { printf '     %s\n' "$*"; }
head_() { printf '\n%s== %s ==%s\n' "$C_B" "$*" "$C_0"; }

pass() { PASSED=$((PASSED+1)); printf '%sPASS%s %s\n' "$C_G" "$C_0" "$1"; }
skip() { SKIPPED=$((SKIPPED+1)); printf '%sSKIP%s %s (%s)\n' "$C_Y" "$C_0" "$1" "${2:-}"; }
fail() {
    FAILED=$((FAILED+1)); FAILED_NAMES+=("$1")
    printf '%sFAIL%s %s\n' "$C_R" "$C_0" "$1"
    [ $# -gt 1 ] && printf '     %s\n' "$2"
    return 0
}

# ------------------------------------------------------------ dmesg watch ---

DMESG_MARK=0

dmesg_mark() { DMESG_MARK=$(dmesg 2>/dev/null | wc -l); }

# Anything here means the kernel is unhappy. "bad use value" and "session count
# underflow" are the module's own consistency complaints and count too.
#
# \b matters on the first two: the module prints "xt_NAT DEBUG:" and
# "... ERROR: ..." constantly, and an unanchored BUG: matches every DEBUG:
# line, which turned every ordinary load into a fake splat.
DMESG_BAD=(
    '\bBUG:' 'WARNING:' 'KASAN' 'UBSAN' '\bOops' 'general protection'
    'kernel NULL pointer' 'INFO: possible' 'possible circular'
    'suspicious RCU' 'RCU-list' 'scheduling while atomic'
    'list_add corruption' 'list_del corruption' 'refcount_t' 'use-after-free'
    'slab-out-of-bounds' 'stack-out-of-bounds' 'soft lockup' 'hard LOCKUP'
    'bad use value' 'session count underflow'
)

dmesg_check() {
    local name=$1 out pat
    pat=$(IFS='|'; echo "${DMESG_BAD[*]}")
    out=$(dmesg 2>/dev/null | tail -n +$((DMESG_MARK + 1)) \
          | grep -E "$pat" | head -20)
    if [ -n "$out" ]; then
        fail "$name (kernel splat)" "$(echo "$out" | head -5)"
        echo "$out" | sed 's/^/     | /'
        return 1
    fi
    return 0
}

# ------------------------------------------------------------ environment ---

need() { command -v "$1" >/dev/null 2>&1; }

check_env() {
    local missing=()
    for t in ip iptables insmod rmmod python3; do
        need $t || missing+=("$t")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        say "missing required tools: ${missing[*]}"
        exit 1
    fi
    [ "$(id -u)" = 0 ] || { say "must run as root"; exit 1; }
    [ -f "$MODULE" ] || { say "module not found: $MODULE (run make first)"; exit 1; }

    if [ "${XT_NAT_TEST_FORCE:-0}" != 1 ]; then
        local virt="none"
        need systemd-detect-virt && virt=$(systemd-detect-virt 2>/dev/null || echo none)
        if [ "$virt" = none ] && ! grep -qi 'qemu\|kvm\|bochs' /sys/class/dmi/id/sys_vendor 2>/dev/null; then
            say "This does not look like a VM ($(cat /sys/class/dmi/id/sys_vendor 2>/dev/null), uptime $(cut -d. -f1 /proc/uptime)s)."
            say ""
            say "This test insmods an out-of-tree NAT module that rewrites packet"
            say "headers, and adds rules to the live raw/PREROUTING and FORWARD"
            say "chains. A bug in the module is a kernel bug, on this kernel."
            say ""
            say "Run it in a throwaway VM:  $0 --vng /path/to/linux"
            say "Override only if you mean it:  XT_NAT_TEST_FORCE=1 $0"
            exit 1
        fi
    else
        say "${C_Y}XT_NAT_TEST_FORCE is set - running against the live kernel.${C_0}"
    fi

    # Where to find libxt_NAT.so. Prefer the build directory so the test does
    # not depend on 'make linstall' having been run; xtables searches a
    # colon-separated list, so keep the system directory too.
    local sysdir
    sysdir=$(pkg-config --variable xtlibdir xtables 2>/dev/null)
    [ -n "$sysdir" ] || sysdir=/usr/lib/xtables
    export XTABLES_LIBDIR="$SRCDIR:$sysdir"
    if [ ! -f "$SRCDIR/libxt_NAT.so" ] && [ ! -f "$sysdir/libxt_NAT.so" ]; then
        say "libxt_NAT.so not found in $SRCDIR or $sysdir - run 'make' first"
        exit 1
    fi
}

report_kernel_config() {
    local cfg=/boot/config-$(uname -r) opt found=() reader=cat
    if [ -f /proc/config.gz ]; then cfg=/proc/config.gz; reader=zcat; fi
    [ -f "$cfg" ] || { say "${C_Y}note:${C_0} no kernel config found, cannot report debug options"; return; }
    need "$reader" || return
    for opt in KASAN PROVE_LOCKING PROVE_RCU DEBUG_ATOMIC_SLEEP \
               DEBUG_OBJECTS_TIMERS DEBUG_KMEMLEAK SLUB_DEBUG DEBUG_LIST; do
        if $reader "$cfg" 2>/dev/null | grep -q "^CONFIG_${opt}=y"; then
            found+=("$opt")
        fi
    done
    if [ ${#found[@]} -eq 0 ]; then
        say "${C_Y}note:${C_0} no kernel debug options detected - these tests will"
        say "      catch functional breakage but not memory or locking bugs."
        say "      See the header of this script for the config to build."
    else
        info "kernel debug: ${found[*]}"
    fi
}

# -------------------------------------------------------------- topology ---

ipt() { iptables "$@"; }

net_up() {
    ip netns add $NS_SUB
    ip netns add $NS_INET

    ip link add xn-s0 type veth peer name xn-s1
    ip link add xn-i0 type veth peer name xn-i1
    ip link set xn-s1 netns $NS_SUB
    ip link set xn-i1 netns $NS_INET

    ip addr add $SUB_NET.1/24 dev xn-s0
    ip addr add $INET_NET.1/24 dev xn-i0
    ip link set xn-s0 up
    ip link set xn-i0 up

    ip -n $NS_SUB addr add $SUB_NET.2/24 dev xn-s1
    ip -n $NS_SUB link set xn-s1 up
    ip -n $NS_SUB link set lo up
    ip -n $NS_SUB route add default via $SUB_NET.1

    ip -n $NS_INET addr add $INET_NET.2/24 dev xn-i1
    ip -n $NS_INET link set xn-i1 up
    ip -n $NS_INET link set lo up
    # the NAT pool is reached through the DUT
    ip -n $NS_INET route add $POOL_NET via $INET_NET.1

    # keep packets un-coalesced so what the module sees is what we sent
    if need ethtool; then
        ethtool -K xn-s0 gro off gso off tso off >/dev/null 2>&1
        ethtool -K xn-i0 gro off gso off tso off >/dev/null 2>&1
        ip netns exec $NS_SUB ethtool -K xn-s1 gro off gso off tso off >/dev/null 2>&1
        ip netns exec $NS_INET ethtool -K xn-i1 gro off gso off tso off >/dev/null 2>&1
    fi

    sysctl -qw net.ipv4.ip_forward=1
    sysctl -qw net.ipv4.conf.all.rp_filter=0
    sysctl -qw net.ipv4.conf.default.rp_filter=0
}

net_down() {
    ip netns del $NS_SUB 2>/dev/null
    ip netns del $NS_INET 2>/dev/null
    ip link del xn-s0 2>/dev/null
    ip link del xn-i0 2>/dev/null
}

# Insert at the head of each chain rather than appending, so an existing DROP
# further down cannot shadow us - and delete exactly what we inserted rather
# than flushing. Never touch the chain policies. If this ever runs somewhere
# it should not, it must not take the host's firewall with it.
rules_up() {
    ipt -t raw -I PREROUTING 1 -s $SUB_NET.0/24 -j CT --notrack
    ipt -t raw -I PREROUTING 1 -d $POOL_NET -j CT --notrack
    ipt -t raw -I PREROUTING 1 -d $POOL_NET -j NAT --dnat
    # return direction is DNATed in raw, then traverses FORWARD normally
    ipt -I FORWARD 1 -i xn-i0 -o xn-s0 -d $SUB_NET.0/24 -j ACCEPT
    # the NAT target is terminating for what it accepts, so it goes first
    ipt -I FORWARD 1 -s $SUB_NET.0/24 -o xn-i0 -j NAT --snat
}

rules_down() {
    ipt -D FORWARD -s $SUB_NET.0/24 -o xn-i0 -j NAT --snat 2>/dev/null
    ipt -D FORWARD -i xn-i0 -o xn-s0 -d $SUB_NET.0/24 -j ACCEPT 2>/dev/null
    ipt -t raw -D PREROUTING -d $POOL_NET -j NAT --dnat 2>/dev/null
    ipt -t raw -D PREROUTING -d $POOL_NET -j CT --notrack 2>/dev/null
    ipt -t raw -D PREROUTING -s $SUB_NET.0/24 -j CT --notrack 2>/dev/null
    return 0
}

# insmod loads exactly the file it is given and resolves nothing, so every
# symbol xt_NAT imports has to already be in the kernel. xt_register_target()
# lives in x_tables, which on a freshly booted machine nothing has loaded yet -
# the first insmod then fails with "Unknown symbol in module". It works on a
# desktop only because something else pulled x_tables in first. The test rules
# need the rest. (modprobe xt_NAT after make install/depmod handles this by
# itself; insmod of a build-directory .ko does not.)
preload_deps() {
    local m
    for m in x_tables ip_tables iptable_raw iptable_filter nf_conntrack xt_CT; do
        modprobe $m 2>/dev/null
    done
    return 0
}

mod_up()       { insmod "$MODULE" nat_pool=$POOL_START-$POOL_END "$@"; }
mod_down()     { rmmod xt_NAT 2>/dev/null; return 0; }
module_loaded() { [ -d /proc/net/NAT ]; }

cleanup() {
    [ "$KEEP" = 1 ] && { say "--keep: leaving topology up"; return; }
    rules_down
    mod_down
    net_down
    rm -rf "$TMPD"
}

nat_stat() {
    # nat_stat "Active NAT sessions" -> number
    sed -n "s/^$1: *//p" /proc/net/NAT/statistics 2>/dev/null | head -1
}

# --------------------------------------------------------------- helpers ---

write_helpers() {
cat >"$TMPD/udp_srv.py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 7777))
s.settimeout(15)
while True:
    d, a = s.recvfrom(2048)
    s.sendto(a[0].encode(), a)          # tell the client which source we saw
EOF

cat >"$TMPD/udp_cli.py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
try:
    s.sendto(b'ping', (sys.argv[1], 7777))
    d, _ = s.recvfrom(2048)
    print(d.decode())
except Exception as e:
    print("ERROR:%s" % e)
EOF

cat >"$TMPD/tcp_srv.py" <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 7778))
s.listen(8)
s.settimeout(15)
while True:
    c, a = s.accept()
    c.recv(4096)
    c.sendall(a[0].encode())
    c.close()
EOF

cat >"$TMPD/tcp_cli.py" <<'EOF'
import socket, sys
try:
    s = socket.create_connection((sys.argv[1], 7778), timeout=5)
    s.sendall(b'x' * 512)               # enough payload to matter for checksums
    print(s.recv(4096).decode())
    s.close()
except Exception as e:
    print("ERROR:%s" % e)
EOF

# UDP to a closed port: the far end answers ICMP port-unreachable, which has to
# come back through the related-ICMP path with a valid outer checksum and a
# correctly un-NATed quoted header, or the local stack will not raise
# ECONNREFUSED on the connected socket.
cat >"$TMPD/icmp_err.py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.connect((sys.argv[1], 9))
s.send(b'x')
try:
    s.recv(100)
    print("NOERROR")
except ConnectionRefusedError:
    print("REFUSED")
except socket.timeout:
    print("TIMEOUT")
except Exception as e:
    print("ERROR:%s" % e)
EOF

# Malformed ICMP error: the quoted IP header claims ihl=15 (60 bytes) but the
# packet is only long enough for 20. The old code validated
# sizeof(struct iphdr) while locating the quoted transport header with
# ihl * 4, so it read and wrote ~32 bytes past the end of the packet.
cat >"$TMPD/icmp_evil.py" <<'EOF'
import socket, struct, sys

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = 0
    for i in range(0, len(b), 2):
        s += (b[i] << 8) + b[i+1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

src, dst = sys.argv[1], sys.argv[2]

# quoted header: ihl=15 in the nibble, only 20 bytes actually present
inner = struct.pack('!BBHHHBBH4s4s',
                    (4 << 4) | 15, 0, 60, 0, 0, 64, socket.IPPROTO_TCP, 0,
                    socket.inet_aton(dst), socket.inet_aton(src))
payload = inner + b'\0' * 8                  # where the quoted ports would be

icmp = struct.pack('!BBHI', 3, 3, 0, 0) + payload
icmp = struct.pack('!BBHI', 3, 3, csum(icmp), 0) + payload

total = 20 + len(icmp)                       # 56 bytes: passes the old check
iph = struct.pack('!BBHHHBBH4s4s',
                  (4 << 4) | 5, 0, total, 0, 0, 64, socket.IPPROTO_ICMP, 0,
                  socket.inet_aton(src), socket.inet_aton(dst))

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
for _ in range(20):
    s.sendto(iph + icmp, (dst, 0))
print("SENT")
EOF

cat >"$TMPD/churn.py" <<'EOF'
import socket, sys
# Open N sessions from distinct source ports and leave them idle. The target
# must be an address that never answers: a replied session gets a 300s
# timeout instead of 30s and would outlive the test's patience.
n = int(sys.argv[2])
socks = []
for i in range(n):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 0))
    try:
        s.sendto(b'x', (sys.argv[1], 7777))
    except Exception:
        pass
    socks.append(s)
print("OPENED:%d" % len(socks))
EOF

cat >"$TMPD/flood.py" <<'EOF'
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
end = time.time() + float(sys.argv[2])
i = 0
while time.time() < end:
    try:
        s.sendto(b'x' * 64, (sys.argv[1], 7777 + (i % 64)))
    except Exception:
        pass
    i += 1
EOF
}

srv_start() {
    ip netns exec $NS_INET python3 "$TMPD/udp_srv.py" >/dev/null 2>&1 &
    SRV_UDP=$!
    ip netns exec $NS_INET python3 "$TMPD/tcp_srv.py" >/dev/null 2>&1 &
    SRV_TCP=$!
    sleep 0.5
}

srv_stop() {
    kill ${SRV_UDP:-0} ${SRV_TCP:-0} 2>/dev/null
    wait ${SRV_UDP:-0} ${SRV_TCP:-0} 2>/dev/null
}

# ----------------------------------------------------------------- tests ---

t_load() {
    local n="module loads and exports /proc"
    preload_deps
    dmesg_mark
    if ! mod_up 2>"$TMPD/err"; then
        fail "$n" "insmod failed: $(head -1 "$TMPD/err")"
        return
    fi
    for f in sessions users statistics; do
        [ -r /proc/net/NAT/$f ] || { fail "$n" "/proc/net/NAT/$f missing"; return; }
    done
    dmesg_check "$n" && pass "$n"
}

t_rules() {
    local n="iptables accepts the NAT target"
    dmesg_mark
    if ! rules_up 2>"$TMPD/err"; then
        fail "$n" "$(head -2 "$TMPD/err")"; return
    fi
    dmesg_check "$n" && pass "$n"
}

t_udp() {
    local n="UDP: SNAT out, DNAT back"
    dmesg_mark
    local got
    got=$(ip netns exec $NS_SUB python3 "$TMPD/udp_cli.py" $INET_NET.2)
    case "$got" in
        $POOL_PREFIX*) dmesg_check "$n" && pass "$n" && info "server saw $got" ;;
        *)             fail "$n" "server saw '$got', expected a $POOL_PREFIX* address" ;;
    esac
}

t_tcp() {
    local n="TCP: handshake and payload through the NAT"
    dmesg_mark
    local got
    got=$(ip netns exec $NS_SUB python3 "$TMPD/tcp_cli.py" $INET_NET.2)
    case "$got" in
        $POOL_PREFIX*) dmesg_check "$n" && pass "$n" ;;
        *)             fail "$n" "server saw '$got'" ;;
    esac
}

t_icmp() {
    local n="ICMP echo through the NAT"
    dmesg_mark
    if ip netns exec $NS_SUB ping -c 3 -W 2 -q $INET_NET.2 >/dev/null 2>&1; then
        dmesg_check "$n" && pass "$n"
    else
        fail "$n" "ping failed"
    fi
}

t_tables() {
    local n="/proc reflects live sessions and users"
    dmesg_mark
    local sess users act
    # both files end with their own total; do not count '->' lines, the
    # sessions header contains one
    sess=$(sed -n 's/^Total translations: *//p' /proc/net/NAT/sessions 2>/dev/null)
    users=$(sed -n 's/^Total users: *//p' /proc/net/NAT/users 2>/dev/null)
    act=$(nat_stat "Active NAT sessions")
    if [ "${sess:-0}" -gt 0 ] && [ "${users:-0}" -gt 0 ]; then
        dmesg_check "$n" && pass "$n" && info "$sess sessions, $users users, active=$act"
    else
        fail "$n" "sessions=$sess users=$users"
    fi
}

t_icmp_error() {
    # Covers the related-ICMP path end to end: the quoted header must be
    # un-NATed and the outer ICMP checksum recomputed, or the subscriber's
    # stack silently drops the error and we get TIMEOUT instead of REFUSED.
    local n="ICMP error: translated, checksum valid, delivered"
    dmesg_mark
    local got
    got=$(ip netns exec $NS_SUB python3 "$TMPD/icmp_err.py" $INET_NET.2)
    case "$got" in
        REFUSED) dmesg_check "$n" && pass "$n" ;;
        TIMEOUT) fail "$n" "no ICMP error delivered - bad checksum or untranslated quoted header" ;;
        *)       fail "$n" "got '$got'" ;;
    esac
}

t_icmp_malformed() {
    local n="malformed ICMP error (quoted ihl=15, truncated) is rejected"
    dmesg_mark
    ip netns exec $NS_INET python3 "$TMPD/icmp_evil.py" $INET_NET.2 $POOL_START >/dev/null 2>&1
    sleep 1
    dmesg_check "$n" || return
    # the module must still be healthy afterwards
    local got
    got=$(ip netns exec $NS_SUB python3 "$TMPD/udp_cli.py" $INET_NET.2)
    case "$got" in
        $POOL_PREFIX*) pass "$n" ;;
        *)             fail "$n" "NAT broken after malformed input: '$got'" ;;
    esac
}

t_target_validation() {
    local n="rule without --snat/--dnat is rejected"
    dmesg_mark
    if ipt -A FORWARD -s $SUB_NET.0/24 -j NAT 2>/dev/null; then
        ipt -D FORWARD -s $SUB_NET.0/24 -j NAT 2>/dev/null
        fail "$n" "iptables accepted a NAT rule with no direction"
        return
    fi
    if ipt -A FORWARD -s $SUB_NET.0/24 -j NAT --snat --dnat 2>/dev/null; then
        ipt -D FORWARD -s $SUB_NET.0/24 -j NAT --snat --dnat 2>/dev/null
        fail "$n" "iptables accepted --snat --dnat together"
        return
    fi
    dmesg_check "$n" && pass "$n"
}

t_bad_params() {
    local n="degenerate module parameters are refused, not oopsed"
    dmesg_mark
    rules_down
    mod_down
    sleep 0.5

    # a reversed/empty pool must be refused
    if insmod "$MODULE" nat_pool=0.0.0.0-0.0.0.0 2>/dev/null; then
        rmmod xt_NAT 2>/dev/null
        fail "$n" "an empty NAT pool was accepted"
        mod_up; rules_up; return
    fi

    # nat_hash_size=0 makes kzalloc() return ZERO_SIZE_PTR, which is not NULL,
    # so the allocation check passes and the first lookup dereferences it
    local bad
    for bad in "nat_hash_size=0" "nat_hash_size=-1" "users_hash_size=0"; do
        if insmod "$MODULE" nat_pool=$POOL_START-$POOL_END $bad 2>/dev/null; then
            rmmod xt_NAT 2>/dev/null
            fail "$n" "$bad was accepted"
            mod_up; rules_up; return
        fi
    done

    mod_up || { fail "$n" "could not reload module"; return; }
    rules_up
    dmesg_check "$n" && pass "$n"
}

t_capture() {
    local n="traffic stays correct with a capture attached"
    need tcpdump || { skip "$n" "tcpdump not installed"; return; }
    dmesg_mark
    tcpdump -i xn-s0 -n -c 200 -w /dev/null >/dev/null 2>&1 &
    local td=$!
    sleep 1
    local got
    got=$(ip netns exec $NS_SUB python3 "$TMPD/udp_cli.py" $INET_NET.2)
    kill $td 2>/dev/null; wait $td 2>/dev/null
    case "$got" in
        $POOL_PREFIX*) dmesg_check "$n" && pass "$n" ;;
        *)             fail "$n" "'$got' while capturing" ;;
    esac
}

t_reload_cycles() {
    local n="20 load/unload cycles leak nothing"
    dmesg_mark
    local before after cycles=20 i
    before=$(sed -n 's/^MemAvailable: *\([0-9]*\).*/\1/p' /proc/meminfo)

    for i in $(seq 1 $cycles); do
        rules_down
        mod_down
        if ! mod_up 2>"$TMPD/err"; then
            fail "$n" "insmod failed on cycle $i: $(head -1 "$TMPD/err")"
            info "check /proc/buddyinfo - the tables are large allocations"
            mod_up 2>/dev/null && rules_up      # leave the rig usable
            return
        fi
        rules_up
        ip netns exec $NS_SUB python3 "$TMPD/udp_cli.py" $INET_NET.2 >/dev/null 2>&1
    done

    after=$(sed -n 's/^MemAvailable: *\([0-9]*\).*/\1/p' /proc/meminfo)
    info "MemAvailable ${before}kB -> ${after}kB over $cycles cycles"

    if [ -w /sys/kernel/debug/kmemleak ]; then
        echo scan > /sys/kernel/debug/kmemleak
        sleep 6
        echo scan > /sys/kernel/debug/kmemleak
        local leaks
        leaks=$(grep -c 'xt_NAT\|nat_htable\|nat_tg_init' /sys/kernel/debug/kmemleak 2>/dev/null)
        if [ "${leaks:-0}" -gt 0 ]; then
            fail "$n" "kmemleak reports $leaks xt_NAT allocations"
            grep -A3 'xt_NAT' /sys/kernel/debug/kmemleak 2>/dev/null | head -20 | sed 's/^/     | /'
            return
        fi
        info "kmemleak: clean"
    else
        info "kmemleak unavailable (needs CONFIG_DEBUG_KMEMLEAK + debugfs)"
    fi
    dmesg_check "$n" && pass "$n"
}

t_rmmod_under_load() {
    # The teardown used to call del_timer_sync() while holding the lock the
    # timer callback takes. If that regresses, this hangs rather than fails.
    local n="rmmod completes while the GC timer is busy"
    module_loaded || { skip "$n" "module not loaded"; return; }
    dmesg_mark
    ip netns exec $NS_SUB python3 "$TMPD/flood.py" $INET_NET.2 6 >/dev/null 2>&1 &
    local fl=$!
    sleep 2
    rules_down
    timeout 30 rmmod xt_NAT 2>"$TMPD/err"
    local rc=$?
    kill $fl 2>/dev/null; wait $fl 2>/dev/null
    case $rc in
        0)   mod_up; rules_up; dmesg_check "$n" && pass "$n" ;;
        124) fail "$n" "rmmod did not complete within 30s - deadlock" ;;
        *)   fail "$n" "rmmod failed: $(head -1 "$TMPD/err")"
             mod_up 2>/dev/null && rules_up ;;
    esac
}

t_aging() {
    # The GC decrements a session's timeout once per full table sweep (~10s),
    # from 30, so an idle session takes roughly a minute to disappear. This is
    # the window in which the old free-the-shared-session bug fired, so it is
    # worth running under KASAN.
    local n="sessions age out and the tables drain"
    dmesg_mark
    # .3 is unused, so nothing ever replies and the sessions keep the 30s
    # unreplied timeout: ~5 sweeps, so under a minute to disappear
    ip netns exec $NS_SUB python3 "$TMPD/churn.py" $INET_NET.3 300 >/dev/null 2>&1
    sleep 2
    local peak; peak=$(nat_stat "Active NAT sessions")
    info "peak active sessions: ${peak:-?}"
    [ "${peak:-0}" -gt 0 ] || { fail "$n" "no sessions were created"; return; }

    local i act
    for i in $(seq 1 24); do          # up to 120s
        sleep 5
        act=$(nat_stat "Active NAT sessions")
        [ "${act:-1}" = 0 ] && break
    done
    dmesg_check "$n" || return
    if [ "${act:-1}" = 0 ]; then
        pass "$n"
    else
        fail "$n" "$act sessions still active after 120s (was $peak)"
    fi
}

t_final_stats() {
    head_ "counters"
    cat /proc/net/NAT/statistics 2>/dev/null | sed 's/^/     /'
    local tried created
    tried=$(nat_stat "Tried NAT sessions")
    created=$(nat_stat "Created NAT sessions")
    if [ -n "${tried:-}" ] && [ -n "${created:-}" ] && [ "$tried" -gt "$created" ]; then
        info "note: ${C_Y}$((tried - created)) session creations failed${C_0} (limits, or no free port)"
    fi
}

# ------------------------------------------------------------------ main ---

usage() {
    sed -n '2,/^$/s/^# \{0,1\}//p' "$0"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --soak) SOAK=1 ;;
        --keep) KEEP=1 ;;
        --vng)  shift; VNG_KDIR=${1:-} ;;
        -h|--help) usage ;;
        *) say "unknown option: $1"; exit 1 ;;
    esac
    shift
done

if [ -n "$VNG_KDIR" ]; then
    need vng || { say "virtme-ng (vng) not installed"; exit 1; }
    args=""
    [ $SOAK = 1 ] && args="$args --soak"
    say "launching: vng --run $VNG_KDIR --user root -- $0$args"
    exec vng --run "$VNG_KDIR" --cpus 4 --memory 2G --user root -- \
         env XT_NAT_TEST_FORCE=1 MODULE="$MODULE" bash "$0" $args
fi

check_env
trap cleanup EXIT INT TERM

head_ "xt_NAT test run: $(uname -r)"
info "module: $MODULE"
report_kernel_config

# Start from a clean slate; a leftover module from a previous run would make
# every result meaningless.
mod_down
net_down
sleep 0.2

net_up
write_helpers

t_load
t_rules
srv_start

t_udp
t_tcp
t_icmp
t_tables
t_icmp_error
t_icmp_malformed
t_target_validation
t_capture
t_bad_params
t_reload_cycles
t_rmmod_under_load

if [ $SOAK = 1 ]; then
    t_aging
else
    skip "sessions age out and the tables drain" "use --soak"
fi

srv_stop
t_final_stats

head_ "summary"
printf '     %spassed %d%s, %sfailed %d%s, skipped %d\n' \
       "$C_G" $PASSED "$C_0" "$C_R" $FAILED "$C_0" $SKIPPED
if [ $FAILED -gt 0 ]; then
    for f in "${FAILED_NAMES[@]}"; do printf '     %s- %s%s\n' "$C_R" "$f" "$C_0"; done
    exit 1
fi
exit 0
