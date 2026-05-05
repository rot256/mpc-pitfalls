---
title: "SPDZ MAC check under multi-threading"
class: "Others"
source: "sequential-used-concurrently.md"
---

### SPDZ MAC check under multi-threading

**What can go wrong.** SPDZ is proven secure in the UC model assuming a
**single-threaded** execution environment. The MAC check sub-protocol verifies that
values opened during the computation are correctly authenticated by the shared MAC key
$\alpha$. The security proof assumes the MAC check runs atomically: all threads see
consistent state from the start of verification until its completion (or abort). When
an implementation splits the MAC check across threads — opening a value in one thread
while another thread concurrently runs its own MAC check — the intermediate state the
proof treated as private leaks between threads, and the verification that the proof
treats as atomic is interleaved with other cryptographic operations.

**Security implication.** The paper
[*Rushing at SPDZ: On the Practical Security of Malicious MPC Implementations*](https://eprint.iacr.org/2025/789)
(IEEE S&P 2025) shows a malicious party running a modified client exploits multi-thread
interleaving to extract information about the global MAC key $\alpha$ from concurrent
MAC check instances, then forges MACs on arbitrary output values. The result is full
compromise of output integrity: the adversary can make the SPDZ computation output any
value of its choosing, defeating the malicious-security guarantee that SPDZ is
specifically designed to provide. Three SPDZ implementations were analyzed:

| Repository | Vulnerable | Notes |
|-----------|-----------|-------|
| [data61/MP-SPDZ](https://github.com/data61/MP-SPDZ) | Yes (patched) | Fixes shipped in v0.3.3 and v0.3.7 |
| [KULeuven-COSIC/SCALE-MAMBA](https://github.com/KULeuven-COSIC/SCALE-MAMBA) | Yes | No public patch commit; uses quarterly private release cycle |
| [aicis/fresco](https://github.com/aicis/fresco) | No | Does not support cross-thread secret transfer by design |

**How to avoid.** Treat the MAC check sub-protocol as an **atomic critical section**
across all threads. Three concrete rules:

1. *Mutual exclusion on the MAC check.* A mutex or semaphore prevents two threads from
   executing overlapping MAC-check instances, including the possible abort path.
2. *Unconditional verification on every open.* The MAC `check()` call must fire
   whenever secret values are opened, regardless of whether the opened values reach an
   output gate.
3. *Design-level isolation.* Where possible, avoid sharing secret state across threads
   entirely. Fresco's design-by-construction single-thread-per-session model is a
   useful reference point.

**Example: MP-SPDZ `POpen` and `Commit_And_Open_` race conditions.** Two concrete bugs
were found and patched in MP-SPDZ in July 2023.

*Bug 1 — Missing MAC check in multi-threaded `POpen`*
([commit `5e714b2`](https://github.com/data61/MP-SPDZ/commit/5e714b2)). The
`SubProcessor<T>::POpen()` function opens secret values. The MAC verification call
`check()` was only triggered by an explicit output-gate condition (`inst.get_n()`), so
in multi-threaded programs the opened values were never MAC-checked before use:

```cpp
// FILE: Processor/Processor.hpp — MP-SPDZ (vulnerable, prior to fix)

// Opening loop — MAC check only triggered by inst.get_n(), not by nthreads
if (inst.get_n())
{
    // ... batched open processing ...
    C[*it + i] = MC.finalize_open();
}
// check() is never called when inst.get_n() is false,
// even if multiple threads are concurrently opening values
```

The fix extends both conditions to also fire when threads are active:

```cpp
// FILE: Processor/Processor.hpp — MP-SPDZ (fixed)

if (inst.get_n() or BaseMachine::s().nthreads > 0)
{
    C[*it + i] = MC.finalize_open();
    if (inst.get_n() or BaseMachine::s().nthreads > 0)
        check();
}
```

*Bug 2 — Race condition in `Commit_And_Open_`*
([commit `b86f29b`](https://github.com/data61/MP-SPDZ/commit/b86f29b)). Inside
`Tools/Subroutines.cpp`, the coordinator was signaled as finished *before* the
commitment-opening validation loop ran. A second thread waiting on the coordinator
could therefore observe the "finished" state and proceed with values that had not yet
been verified:

```cpp
// FILE: Tools/Subroutines.cpp — MP-SPDZ (vulnerable)

P.Broadcast_Receive(Open_data);
coordinator.finished();                    // ← signals completion before verifying

for (int i = 0; i < P.num_players(); i++)
    if (!Open(datas[i], Comm_data[i], Open_data[i], i))
        throw invalid_commitment();
```

The fix moves the signal to after the validation loop:

```cpp
// FILE: Tools/Subroutines.cpp — MP-SPDZ (fixed)

P.Broadcast_Receive(Open_data);
for (int i = 0; i < P.num_players(); i++)
    if (!Open(datas[i], Comm_data[i], Open_data[i], i))
        throw invalid_commitment();

coordinator.finished();                    // ← now after verifying
```

The attack exploits the race by having a malicious party controlling Thread B observe
that Thread A's coordinator has finished and immediately proceed to use the opened
values in its own MAC check instance, before A has confirmed those values are
authenticated. By carefully timing two concurrent MAC check instances the adversary
extracts information about $\alpha$ through the unauthenticated intermediate state,
then uses this to forge MACs on arbitrary output values.

<!--
