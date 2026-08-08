# TODO

Ideas that have been thought through but not built. Each one says what it costs
and, where it matters, why the obvious alternative was rejected — so the
reasoning does not have to be redone.

Nothing here is scheduled. The rule from `TESTING.md` applies: measure before
optimising. Four earlier theories about where time went were all falsified.

## Port allocator

### 1. Free-port counter per (NAT address, protocol)

`search_free_l4_port()` has no early-out for an exhausted bitmap. A subscriber
under its per-user cap, on a NAT address with no free ports, scans the whole
8 KB every packet — forward to `hi`, then wrapped from `lo` — and returns 0.

A `used`/free counter next to each bitmap makes that rejection O(1). Four bytes
per (address, protocol); for a 254-address pool, 3 KB against 6 MB of bitmap.

This is the cheapest item here and it removes a pathological case, not a
marginal one.

**Not currently benchmarked.** `--pool 1` looks like it covers exhaustion but
does not: those rejections come from `check_user_limits()` hitting the
4096-per-user cap *before* the port search runs. The "rejects in O(1)" line in
`TESTING.md` refers to that path, not this one.

### 2. Two-level summary bitmap

One bit per leaf *word*, set when that word is all-ones:

| level | size per (addr, proto) | cachelines |
|---|---|---|
| leaf (65536 bits) | 8 KB | 128 |
| summary (1024 bits) | **128 B** | **2** |

Allocation becomes: scan the 128-byte summary for a word with a hole, load that
one leaf word, `__ffs(~word)`. Worst case ~3 cacheline touches instead of up to
256. For a 254-address pool the summary layer totals 97 KB — L2-resident —
against 6 MB of leaf, and that cache footprint is the real win.

Keep the summary **advisory**: allow it to be stale in either direction and fall
back to the existing full scan before declaring exhaustion. Then it needs no
extra atomics on the fast path and no correctness argument beyond "a stale hint
costs you a different port number". Maintaining it exactly would put a second
atomic on the word-becomes-full and word-gains-a-hole transitions, and would
have to handle two CPUs racing a fill against a free.

Only pays in the near-full regime. In a sparse pool the first
`test_and_set_bit()` succeeds and the scan never runs.

### 3. SIMD — rejected, do not revisit without new information

x86-64 AVX2/AVX-512 over the port bitmap was considered and is the wrong tool,
for two independent reasons.

**`kernel_fpu_begin()` is not free.** It needs `irq_fpu_usable()`, does
XSAVE/XRSTOR of FPU state, disables preemption, and still requires a scalar
fallback. Crypto and RAID6 pay that because they amortise over kilobytes per
call. Here the common case is a single `test_and_set_bit()`.

**The scan is bound by cachelines touched, not ALU throughput** — which is the
reason that would survive even if the FPU were free:

| | u64 scalar | AVX-512 |
|---|---|---|
| loads to scan one 8 KB bitmap | 1024 | 128 |
| **cachelines touched** | **128** | **128** |

Wider registers read the same bytes. Instruction count drops ~8x, memory traffic
does not, and at a 6 MB working set the scan is at L3/memory latency where width
is irrelevant. Item 2 attacks bytes touched, which is why it wins and this does
not.

Note that the **scalar** bit extensions are already in use and cost nothing:
POPCNT, LZCNT/TZCNT and BMI1/BMI2 are general-purpose-register instructions with
no FPU state, and the kernel's `find_next_zero_bit()` patches in `tzcnt` through
alternatives.

## Benchmarking

### 4. `--fill <percent>` mode for `bench-cps.sh`

Nothing in the suite enters the regime items 1 and 2 target. Sparse pools hit
`test_and_set_bit()` on the first try; exhausted ones reject at the user cap.
A mode that loads a pool to 95–99% and then measures allocation cost would show
whether either is worth building. **This should land before item 1 or 2.**

### 5. Raise the benchmark's resolution

At ~750k cps the rig is generator-bound and two runs of the same build differ by
about 9%, against 1.9% at one NAT address earlier. Anything smaller than that
now hides. Either drive it from more than one guest, or standardise on a
configuration with a tighter band for per-session changes.

### 6. Measure the DNAT reply path

The 1.78M pps forwarding figure is SNAT-direction only. Both directions share
the lookup, so the reply path is inferred rather than measured.

## Coverage

### 7. Run the remaining CI legs

`testing-kernels.yaml` has eight kernels. The 6.19 leg has been reproduced
locally and passes; the other seven have never been run. It is also
`workflow_dispatch` only.

### 8. `--kdir` on something other than 7.0

KASAN and lockdep runs have only ever used a 7.0 kernel. The compat shims that
matter — `sockaddr_unsized` at 6.19, `skb_ensure_writable` at 5.2,
`timer_delete_sync` at 6.16 — are exactly what a single-version debug run cannot
exercise.

## Protocol

### 9. IPFIX export

Considered alongside NetFlow v9. The template mechanism is close enough that
much of the v9 path would be reused, and IEs 225/227/230 carry over. Worth doing
if a collector in the deployment path needs it; not otherwise, since v9 already
carries the NAT event data and export was measured at −0.2% (free).
