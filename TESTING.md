# Testing and benchmarking xt_CGNAT

Everything here runs in a throwaway VM. Nothing needs to touch the machine you
are working on, and it should not: a bug in this module is a kernel bug.

## Quick start

```sh
./run-vm.sh                          # functional suite, ~33s warm
./run-vm.sh --kdir ~/src/linux-7.0   # same, under KASAN + lockdep
./run-vm.sh --bench                  # suite + session rate benchmark
./run-vm.sh --soak                   # + session aging (adds ~2 min)
```

Results land in `vm-results/`: `report.md`, `console.log`, `guest.log`,
`dmesg.txt`, `lock_stat.txt`, `env.txt`. Exit status is the suite's, so it
drops straight into CI.

First run downloads an Ubuntu cloud image (~820 MB, cached) and installs a
toolchain in the guest; it then saves that as `prepared-<release>.qcow2` and
later runs skip both. Cold 112s, warm 33s, and a warm run needs no network.

## What each mode actually proves

| mode | kernel | catches |
|---|---|---|
| default | cloud image's own | functional breakage only |
| `--kdir` | yours, with debug options | use-after-free, lock inversion, RCU misuse, leaks |

**A pass on the default kernel is much weaker than it looks.** No distro ships
KASAN or lockdep. The report prints a `kernel debug:` line saying which options
were actually present — read it before trusting a green run. If it says
`none (no readable kernel config)`, the run proved nothing about memory safety.

### Building a debug kernel

```sh
./run-vm.sh --print-kconfig > /tmp/frag
cd ~/src/linux-7.0
make defconfig
./scripts/kconfig/merge_config.sh -m .config /tmp/frag
make olddefconfig
make -j$(nproc)                      # bzImage AND modules
./run-vm.sh --kdir ~/src/linux-7.0
```

`make bzImage` alone is not enough: an external module links against
`Module.symvers`, which only the modules build produces. Without it modpost
reports every kernel symbol as undefined, which looks like broken code and is
not. `run-vm.sh` checks for it up front.

The fragment is not optional decoration. Beyond the debug options it carries
things without which the rig cannot run at all:

- `NETFILTER_XTABLES_LEGACY` → `IP_NF_IPTABLES_LEGACY` → `IP_NF_RAW`. 7.0 moved
  the legacy tables behind a new gate; without them there is no raw table for
  `-j CT --notrack`.
- `NF_TABLES` + `NFT_COMPAT`. A current distro's iptables is the nft backend and
  reaches xt targets through `nft_compat`; without these `-j CGNAT` cannot load.
- `IKCONFIG_PROC`, so the guest can report which debug options it has.
- 9p, veth, namespaces, virtio.

## Benchmarks

```sh
./run-vm.sh --bench-only --bench-args "--duration 8 --pool-sweep"
./run-vm.sh --bench-only --bench-args "--pool 254 --duration 8"     # unsaturated
./run-vm.sh --bench-only --bench-args "--pool 1 --duration 40"      # exhausted
./run-vm.sh --bench-only --bench-args "--gc-cost"
./run-vm.sh --bench-only --bench-args "--netflow"
./run-vm.sh --bench-only --bench-args "--pool 1 --duration 40 --quarantine"
```

`cps-gen.c` drives unique (source address, source port) pairs with AF_PACKET and
`sendmmsg()`, so it hands complete frames to the device and skips the local
routing and socket paths — what is measured is the NAT, not the generator.

`--pool-sweep` runs 1, 2, 4, 8, 16 NAT addresses. It was written when
`create_session_lock[]` — one spinlock per NAT address — was the constraint. It
no longer is, so the sweep now mostly measures *pool capacity*: with the bitmap
allocator, session creation fills the entire port space within the run and cps
comes out as `ports / duration`. Use `--pool 254` for a rate that is not
capacity-bound.

## Methodology

These are not general principles, they are the specific mistakes made while
producing the numbers below.

**Two runs minimum, on both sides.** A single-sample baseline produced a
reported "6.3% regression" that was actually a 5% improvement — the baseline had
simply been a lucky run. Establish the noise band before believing any delta.
Same-build spread here is about 1.9% at one NAT address, 0.7% at sixteen.

**Check the measurement is not measuring nothing.** Every benchmark ran for a
long time with no NetFlow collector configured, so the export path was never
exercised and the numbers carried an unstated caveat. `--netflow` counts the
datagrams that arrive, because an export that silently failed would look exactly
like an export that costs nothing. Likewise, KASAN being enabled was confirmed
by `nm xt_CGNAT.ko | grep __asan` rather than assumed.

**Make the arithmetic reconcile before concluding.** Sessions listed exceeded
the port capacity, which looked like the allocator handing out duplicates —
alarming and wrong. Sessions listed minus duplicate pairs is exactly 64512 both
before and after the bitmap: the duplicates were sessions past timeout 0 whose
ports had legitimately been reassigned.

**Measure before optimising.** Four separate theories about where time went were
falsified: hoisting allocations out of the session lock (0%), per-CPU counters
(0%), the GC sweep (0.2% of a core), and NetFlow export (0.2%). Everything that
mattered was data layout. A cheap experiment cancelled a planned per-CPU NetFlow
rewrite before any of it was written.

**Absolute numbers from this rig are worthless; comparisons are not.** veth on
4 vCPUs in a VM is not a NIC. Use it to compare commits, pool sizes, session
counts and configurations.

## Current baseline

4 vCPUs, 3.3 GB, KVM, Ubuntu 26.04 guest on kernel 7.0.0-28-generic unless
stated. Two-run means. Reproduce with the commands above.

| measurement | value | how |
|---|---|---|
| session setup, unsaturated | **702,558 cps** | `--pool 254 --duration 8`, generator-bound, so a floor |
| session setup, saturated address | 2,995 cps | `--pool 1 --duration 40` |
| tx pps while exhausted | 1,296,840 | same; the module rejects in O(1) |
| memory per session | **64 bytes** | one cacheline, one allocation |
| GC cost at rest | 0.2–0.3% of one core | `--gc-cost`, flat to 347k sessions |
| NetFlow export cost | −0.2% (free) | `--netflow`, 18,848 packets delivered |
| functional suite | **14/14** | `--kdir --soak`, KASAN + lockdep, dmesg and kmemleak clean |

With `port_quarantine=1` on a saturated address: 1,612 cps, zero duplicate
`(proto, nat ip, port)`, linked sessions exactly 64512. Off is the default and
sustains 1.9x the rate by recycling ports immediately.

### How it got here

| change | effect on cps |
|---|---|
| port bitmap instead of hash scan | **27×** unsaturated, 530× tx pps while exhausted |
| three objects → one 64-byte cacheline | +18–25% |
| private slab cache, natural alignment | +5% |
| allocations hoisted out of the session lock | 0% |
| per-CPU counters | 0% |

## Known limits

- pps on **established** sessions has never been measured. Every number here is
  session creation. A CGNAT forwards far more packets than it creates sessions,
  so this is the gap that matters most; it needs `cps-gen` to stop advancing the
  source port after a fill phase.
- 4 vCPUs cannot show contention that only appears at 32.
- `--kdir` has been exercised on 7.0 only.
- The CI workflow (`testing-kernels.yaml`) stops at 6.18 and is manually
  triggered, so it cannot see the ≥6.19 build break that `compat.h` now handles.
