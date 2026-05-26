---
title: "MP-SPDZ `POpen` and `Commit_And_Open_` race conditions"
category: concurrency-and-state-handling
subcategory: "SPDZ Multi-Threaded MAC Check"
date: 2023-07-21
primitives: [mac, commitment]
repository: https://github.com/data61/MP-SPDZ
hidden: false
---

Two bugs were found and patched in MP-SPDZ.

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
`Tools/Subroutines.cpp`, a shared `coordinator` object lets one thread signal to the
others that its commitment phase is complete. That signal was raised *before* the
commitment-opening validation loop ran, so a second thread waiting on the coordinator
could observe the "finished" state and proceed with values that had not yet been
verified:

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
