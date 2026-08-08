#
# testnet.sh - the NAT test topology, shared by qemu-tests.sh and bench-cps.sh.
# Sourced, not executed.
#
#      netns xtnat-sub                root netns (DUT)              netns xtnat-inet
#   10.0.0.2 --- xn-s1 <=> xn-s0 10.0.0.1 | 198.51.100.1 xn-i0 <=> xn-i1 --- 198.51.100.2
#                                    xt_NAT, pool 203.0.113.1-4
#
# The NAT pool is deliberately overridable: its size decides how many entries
# create_session_lock[] has, and therefore how much of the session-creation
# path is serialised. bench-cps.sh sweeps it.
#

NS_SUB=${NS_SUB:-xtnat-sub}
NS_INET=${NS_INET:-xtnat-inet}
SUB_NET=${SUB_NET:-10.0.0}
INET_NET=${INET_NET:-198.51.100}
POOL_NET=${POOL_NET:-203.0.113.0/24}
POOL_START=${POOL_START:-203.0.113.1}
POOL_END=${POOL_END:-203.0.113.4}
POOL_PREFIX=${POOL_PREFIX:-203.0.113.}

# The subscriber side is a /16, not a /24. bench-cps.sh needs thousands of
# distinct source addresses: the per-user session cap is 4096 per protocol, so
# with only 254 subscribers that cap binds after ~1M sessions and is the only
# thing any measurement ever sees.
SUB_PLEN=${SUB_PLEN:-16}
SUB_CIDR=${SUB_CIDR:-10.0.0.0/16}

need() { command -v "$1" >/dev/null 2>&1; }

ipt() { iptables "$@"; }

# Where to find libxt_NAT.so. Prefer the build directory so nothing depends on
# 'make linstall' having been run; xtables searches a colon-separated list, so
# keep the system directory too.
xtables_libdir_setup() {
    local sysdir
    sysdir=$(pkg-config --variable xtlibdir xtables 2>/dev/null)
    [ -n "$sysdir" ] || sysdir=/usr/lib/xtables
    export XTABLES_LIBDIR="${SRCDIR}:$sysdir"
    [ -f "$SRCDIR/libxt_NAT.so" ] || [ -f "$sysdir/libxt_NAT.so" ]
}

net_up() {
    ip netns add $NS_SUB
    ip netns add $NS_INET

    ip link add xn-s0 type veth peer name xn-s1
    ip link add xn-i0 type veth peer name xn-i1
    ip link set xn-s1 netns $NS_SUB
    ip link set xn-i1 netns $NS_INET

    ip addr add $SUB_NET.1/$SUB_PLEN dev xn-s0
    ip addr add $INET_NET.1/24 dev xn-i0
    ip link set xn-s0 up
    ip link set xn-i0 up

    ip -n $NS_SUB addr add $SUB_NET.2/$SUB_PLEN dev xn-s1
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
    return 0
}

# Insert at the head of each chain rather than appending, so an existing DROP
# further down cannot shadow us - and delete exactly what we inserted rather
# than flushing. Never touch the chain policies. If this ever runs somewhere
# it should not, it must not take the host's firewall with it.
rules_up() {
    ipt -t raw -I PREROUTING 1 -s $SUB_CIDR -j CT --notrack
    ipt -t raw -I PREROUTING 1 -d $POOL_NET -j CT --notrack
    ipt -t raw -I PREROUTING 1 -d $POOL_NET -j NAT --dnat
    # return direction is DNATed in raw, then traverses FORWARD normally
    ipt -I FORWARD 1 -i xn-i0 -o xn-s0 -d $SUB_CIDR -j ACCEPT
    # the NAT target is terminating for what it accepts, so it goes first
    ipt -I FORWARD 1 -s $SUB_CIDR -o xn-i0 -j NAT --snat
}

rules_down() {
    ipt -D FORWARD -s $SUB_CIDR -o xn-i0 -j NAT --snat 2>/dev/null
    ipt -D FORWARD -i xn-i0 -o xn-s0 -d $SUB_CIDR -j ACCEPT 2>/dev/null
    ipt -t raw -D PREROUTING -d $POOL_NET -j NAT --dnat 2>/dev/null
    ipt -t raw -D PREROUTING -d $POOL_NET -j CT --notrack 2>/dev/null
    ipt -t raw -D PREROUTING -s $SUB_CIDR -j CT --notrack 2>/dev/null
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

mod_up()        { insmod "$MODULE" nat_pool=$POOL_START-$POOL_END "$@"; }
mod_down()      { rmmod xt_NAT 2>/dev/null; return 0; }
module_loaded() { [ -d /proc/net/NAT ]; }

nat_stat() {
    # nat_stat "Active NAT sessions" -> number
    sed -n "s/^$1: *//p" /proc/net/NAT/statistics 2>/dev/null | head -1
}
