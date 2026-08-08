# xt_CGNAT

A Full Cone NAT xtables target, built to replace conntrack NAT where a Linux box
has to act as a Carrier-Grade NAT. It keeps its own session tables rather than
using conntrack, and exports NAT events over NetFlow v9.

## Credits

xt_CGNAT is derived from **xt_NAT** by **Andrei Sharaev**
<andr.sharaev@gmail.com>, which is where the design comes from: the paired
inner/outer session tables, endpoint-independent (full cone) semantics, the
timer-driven session GC, the NetFlow v9 event export and the iptables target
interface are all his. The original reported 40 Gbps on 2×Xeon E5-2698 v3 with
Intel X710/XL710/X540 adapters, and was tested against Linux 3.18 and 4.1.

This tree renames the module because `-j NAT` collides with netfilter's own NAT
table and targets, and because it has diverged enough in implementation to be
worth telling apart. What changed since the fork is in the git history and in
[TESTING.md](TESTING.md); the short version is a rewritten session object,
bitmap port allocation, an optional RFC 7422 deterministic mode, a set of
memory-safety fixes, and a test rig.
## Features
* PAT/NAPT work mode - translates many users into a single NAT IP
* Assymetric (Full Cone) NAT - allows inbound connections from any source IP address and any source port, as long as the NAT rule exists
* Support of TCP/UDP/ICMP/Generic IP protocols
* IP Pooling Paired mode - the same NAT IP is used for all sessions of a subscriber
* Endpoint Independent Mapping - the same NAT_IP:NAT_Port mapping is used for traffic sent from same subscriber IP
address and port to any external IP address and port
* Hairpinning - allows communication between two internal subscribers or internal hosts using the NAT IP
* User quotas support. `user_max_sessions` sets the maximum concurrent sessions
per user per protocol (default 4096, max 65535). It is writable at runtime via
`/sys/module/xt_CGNAT/parameters/user_max_sessions`
* No ALGs for FTP/SIP/PPTP are implemented
* Multiple named pools, selected per rule with `--pool`, addable and removable
  at runtime
* Optional **deterministic** port mapping (RFC 7422): the public address and
  port block are computed from the subscriber address, so no per-session log is
  needed to attribute a connection
* NAT events export using **Netflow v9**
* NAT statistics via /proc interface

## Limitations
* IPv4-only target (no IPv6 support).
* IPv4 packets with IP options are dropped (IP header length must be 20 bytes).
* IPv4 fragments with non-zero offset are dropped by the target. Only the first fragment can pass.
* Locally generated ICMP errors (for example "Fragmentation Needed" for PMTUD) are not translated by xt_CGNAT.
* If you disable hardware offloads (GRO/GSO/TSO) you are more likely to see real IP fragments; those will be dropped.
* No ALGs/helpers (FTP/SIP/PPTP/etc.) are implemented.
* For non-TCP/UDP/ICMP protocols, mapping is per-user+proto (port=0), so distinct flows of the same protocol are not separated.

## Pools

`nat_pool` defines one or more pools, comma separated, and a rule picks one:

```
# one unnamed pool, as before
modprobe xt_CGNAT nat_pool=203.0.113.1-203.0.113.4
iptables -A FORWARD -s 10.0.0.0/16 -j CGNAT --snat

# several, one of them deterministic
modprobe xt_CGNAT nat_pool="retail:203.0.113.1-203.0.113.64,\
biz:198.51.100.1-198.51.100.64:10.20.0.0/20:1008"
iptables -A FORWARD -s 10.0.0.0/16  -j CGNAT --snat --pool retail
iptables -A FORWARD -s 10.20.0.0/20 -j CGNAT --snat --pool biz
iptables -t raw -A PREROUTING -d 203.0.113.0/24 -j CGNAT --dnat --pool retail
iptables -t raw -A PREROUTING -d 198.51.100.0/24 -j CGNAT --dnat --pool biz
```

Pools can also be managed at runtime, without reloading the module and dropping
every session:

```
# echo "add wholesale:198.51.100.128-198.51.100.191" > /proc/net/CGNAT/pools
# echo "add trial:203.0.113.200-203.0.113.230:10.30.0.0/22:2016" > /proc/net/CGNAT/pools
# echo "del trial" > /proc/net/CGNAT/pools
# cat /proc/net/CGNAT/pools
```

Deleting is refused while anything still points at the pool - any iptables rule
naming it, or any live session - and the error says which. Drop the rules and
let the sessions age out first. The file is mode 0600 and the write path also
requires `CAP_NET_ADMIN`: it reconfigures the NAT.

Up to 8 pools. Names must be unique and ranges must not overlap - both are
refused, at load and at runtime. Omitting `--pool` selects the first. Per-pool configuration
and counters are in `/proc/net/CGNAT/pools`; `statistics` shows the totals.

Note `/proc/net/CGNAT/users` no longer prints a NAT address: with several pools
a subscriber's public address depends on which rule matched, and that table is
keyed only on the private address. `sessions` has the real mapping.

## Module parameters

All are load-time only unless noted.

| parameter | default | meaning |
|---|---|---|
| `nat_pool` | `127.0.0.1-127.0.0.1` | pool definitions, see [Pools](#pools) |
| `nat_hash_size` | 262144 | session hash buckets, 1024..16777216. Two tables of this size. At more sessions than buckets, chains lengthen and every packet walks further - size it to your expected session count |
| `users_hash_size` | 65536 | subscriber hash buckets, same range |
| `user_max_sessions` | 4096 | concurrent sessions per subscriber **per protocol**, 1..65535. Writable at runtime via `/sys/module/xt_CGNAT/parameters/user_max_sessions` |
| `port_quarantine` | 0 | when a NAT port becomes reusable. 0 releases it as soon as the session stops being findable, which maximises capacity but lets a port be reissued while the old session is still in the table. 1 holds it until the session is unlinked, about one GC sweep later - no port is ever mapped to two sessions, at the cost of holding roughly ten seconds of expiring sessions' ports out of service. Writable at runtime; the choice is fixed per session at creation, so changing it affects only new sessions |
| `nf_dest` | none | NetFlow v9 collectors, `addr:port[,addr:port]` |

Note `user_max_sessions` is a cap on top of whatever ports are available. Under
deterministic mapping the port block is usually the tighter limit: with
endpoint-independent mapping a subscriber consumes one port per distinct source
port, regardless of how many different destinations it talks to, so a 1008-port
block is 1008 concurrent connections in total.

## Migrating from xt_NAT

The rename is not backward compatible. Everything user-visible changed:

| was | is |
|---|---|
| `iptables ... -j NAT --snat` | `iptables ... -j CGNAT --snat` |
| `/proc/net/NAT/{sessions,users,statistics}` | `/proc/net/CGNAT/...` |
| `modprobe xt_NAT` | `modprobe xt_CGNAT` |
| `xt_NAT.ko`, `libxt_NAT.so` | `xt_CGNAT.ko`, `libxt_CGNAT.so` |
| `MODULE_ALIAS ipt_NAT` | `ipt_CGNAT` |

So: update firewall rules, any monitoring that reads `/proc/net/NAT`, and
modprobe/modules-load configuration. Old and new cannot be loaded side by side
under the same rules — the target name is what changed.

Module parameters kept their names, and `nat_pool` accepts the old syntax
unchanged, so a plain `nat_pool=<start>-<end>` still means what it always did.

## Testing

Functional tests, memory/locking checks under KASAN and lockdep, and the
session-rate benchmark all run in a throwaway VM:

```
$ ./run-vm.sh                          # functional suite, ~33s warm
$ ./run-vm.sh --kdir /path/to/linux    # same, under KASAN + lockdep
$ ./run-vm.sh --bench                  # + session setup rate
```

See [TESTING.md](TESTING.md) for what each mode proves, how to build a suitable
debug kernel, the benchmark modes, and the current performance baseline.

## Installation
```
$ make
$ sudo make install
$ sudo depmod -a
```

## Usage
### NAT functionality
* Define NAT Pool for the xt_CGNAT module:
```
$ sudo modprobe xt_CGNAT nat_pool=<Start IP>-<End IP>
```
* Disable conntrack for the traffic that handled by the xt_CGNAT module:
```
$ sudo iptables -t raw -A PREROUTING -s <Users Net> -j CT --notrack
$ sudo iptables -t raw -A PREROUTING -d <NAT Pool Net> -j CT --notrack
```
* Add iptables rule to use xt_CGNAT module for User's traffic (from Internet to Users):
```
$ sudo iptables -t raw -A PREROUTING -d <NAT Pool Net>  -j CGNAT --dnat
$ sudo iptables -A FORWARD -d <Users Net> -i <Uplink iface> -o <Downlink iface> -j ACCEPT
```
* Add iptables rule to use xt_CGNAT module for User's traffic (from Internet to Users):
```
$ sudo iptables -A FORWARD -s <Users Net> -i <Downlink iface> -o <Uplink iface> -j CGNAT –snat
```
### NAT Events Export
Just add ``nf_dest`` option with a list of the **Netflow v9 collectors** to the xt_CGNAT module parameters:
```
$ sudo modprobe xt_CGNAT nat_pool=<Start IP>-<End IP> nf_dest=127.0.0.1:2055
```
## NAT Statistics
NAT statistics are available via the ```/proc/net/CGNAT/*``` directory:
* /proc/net/CGNAT/sessions - NAT sessions for all users
* /proc/net/CGNAT/users - NAT users with their NAT IPs
* /proc/net/CGNAT/statistics - internal counters 
