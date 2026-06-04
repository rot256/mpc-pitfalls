---
title: "SPDZ Multi-Threaded MAC Check"
class: concurrency-and-state-handling
hidden: false
order: 1
source: "sequential-used-concurrently.md"
primitives: [mac, commitment]
bugs: [mp-spdz-mac-check]
display: [mp-spdz-mac-check]
---


**What can go wrong.** SPDZ
([Damgård–Pastro–Smart–Zakarias, 2012](https://eprint.iacr.org/2011/535)) is a maliciously-secure MPC protocol with a dishonest majority, where up to $n-1$ out of $n$ parties can be actively corrupted by an adversary. Shared values are authenticated by an information-theoretic MAC under a global key $\alpha$ that no party knows individually, and openings are verified by a *MAC check* that aborts if the opened value was tampered with. SPDZ is proven secure in the UC framework, which guarantees security under "concurrent execution" with arbitrary independent protocols. However, this guarantee does not extend to a multithreaded SPDZ implementation, where all threads share the same $\alpha$. In particular, when an implementation runs two MAC check instances concurrently in different threads, a malicious party can cheat in one of them to leak the entire MAC key $\alpha$ and use it in the other to forge MACs on arbitrary values.

**Security implication.** The paper
[*Rushing at SPDZ: On the Practical Security of Malicious MPC Implementations*](https://eprint.iacr.org/2025/789) (IEEE S&P 2025) shows that a malicious party can exploit the multi-thread interleaving to cause one MAC-check thread to abort, leaking the global SPDZ MAC key $\alpha$. The adversary then uses the leaked key to manipulate a concurrent thread of the honest parties, e.g. forging MACs on tampered values at will. The paper analyzed three SPDZ implementations and found two, MP-SPDZ and SCALE-MAMBA, vulnerable to this multi-thread MAC interleaving attack. The example below walks through the patches in [MP-SPDZ](https://github.com/data61/MP-SPDZ), one of the two.

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