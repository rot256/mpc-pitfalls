---
title: "SPDZ MAC Check Under Multi-Threading"
class: "Concurrency and State Handling"
order: 1
source: "sequential-used-concurrently.md"
---

### SPDZ MAC Check Under Multi-Threading

**What can go wrong.** SPDZ
([Damgård–Pastro–Smart–Zakarias, 2012](https://eprint.iacr.org/2011/535)) is a maliciously-secure MPC protocol with a dishonest majority, where up to $n-1$ out of $n$ parties can be actively corrupted by an adversary. Shared values are authenticated by an information-theoretic MAC under a global key $\alpha$ that no party knows individually, and openings are verified by a *MAC check* that aborts if the opened value was tampered with. SPDZ is proven secure in the UC framework, which guarantees security under "concurrent execution" with arbitrary independent protocols. However, this guarantee does not extend to a multithreaded SPDZ implementation, where all threads share the same $\alpha$. In particular, when an implementation runs two MAC check instances concurrently in different threads, a malicious party can cheat in one of them to leak the entire MAC key $\alpha$ and use it in the other to forge MACs on arbitrary values.

**Security implication.** The paper
[*Rushing at SPDZ: On the Practical Security of Malicious MPC Implementations*](https://eprint.iacr.org/2025/789)
(IEEE S&P 2025) shows a malicious party running a modified client exploits multi-thread
interleaving to extract information about the global MAC key $\alpha$ from concurrent
MAC check instances, then forges MACs on arbitrary output values. The result is full
compromise of output integrity: the adversary can make the SPDZ computation output any
value of its choosing, defeating the malicious-security guarantee that SPDZ is
specifically designed to provide. The paper analyzed several SPDZ implementations and found two of them vulnerable
to this multi-thread MAC interleaving attack. The example below walks through the
patches in [MP-SPDZ](https://github.com/data61/MP-SPDZ), one of the two. A third
implementation, [Fresco](https://github.com/aicis/fresco), was safe by design since 
its architecture forbids cross-thread secret state.

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
in multi-threaded programs, some opened values could be used without the MAC checks
needed around the open:

```cpp
// FILE: Processor/Processor.hpp — MP-SPDZ (vulnerable, prior to fix)
template <class T>
void SubProcessor<T>::POpen(const Instruction& inst)
{
    if (inst.get_n())
        check();    // ← MAC check only before the loop, only if inst.get_n() is truthy
    // ... batched open setup ...
    for (auto it = reg.begin(); it < reg.end(); it += 2)
        for (int i = 0; i < size; i++)
            C[*it + i] = MC.finalize_open();
    // ← no MAC check after the loop, even when nthreads > 0
}
```

The fix widens the pre-loop gate *and* adds a new post-loop MAC check with the
same gate, so multi-threaded opens trigger both checks:

```cpp
// FILE: Processor/Processor.hpp — MP-SPDZ (fixed, commit 5e714b2)
template <class T>
void SubProcessor<T>::POpen(const Instruction& inst)
{
    if (inst.get_n() or BaseMachine::s().nthreads > 0)
        check();    // ← gate widened to also fire under multi-threading
    // ... batched open setup ...
    for (auto it = reg.begin(); it < reg.end(); it += 2)
        for (int i = 0; i < size; i++)
            C[*it + i] = MC.finalize_open();
    if (inst.get_n() or BaseMachine::s().nthreads > 0)
        check();    // ← NEW: post-loop MAC check, same gate
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
