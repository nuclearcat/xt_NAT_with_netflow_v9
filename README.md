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
