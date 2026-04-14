---
title: "Sequentially Secure Protocol Used Concurrently"
class: "Protocol"
order: 4
---

**Examples:**

- Blind schnorr signatures and ROS.
- Concurrent SPDZ MAC check without appropriate synchronization. To be secure in the presence of multi-threading, the whole MAC check subprotocol needs to be treated as critical section, including the possible abort.

Note that the term "concurrent" is overloaded: It can refer to concurrency in a distributed system (standard in the MPC literature, including UC), or concurrency in the sense of multi-threading/cooperative multi-tasking etc (not covered by standard security models). A multi-threaded MPC implementation might need concurrent security in both meanings of the word.


# DRAFT
By the **modular composition theorem** [Can00], if an MPC protocol is run as part of a larger
system it still behaves as if an incorruptible trusted party carried out the computation, a
powerful guarantee that enables larger protocols to be constructed from secure sub-protocols.
However, this guarantee holds only in the *stand-alone setting*: the MPC protocol may run as
a sub-protocol with arbitrary messages sent before and after, but no other messages may be
sent in parallel *during* its execution.

In practice, MPC protocols often run at the same time as other instances of the same
protocol, other MPC protocols, and other (potentially insecure) protocols. A protocol proven
secure under the stand-alone definition may **not** remain secure in this setting. The
standard solution is **Universal Composability (UC)** [Can01]: any UC-secure protocol is
guaranteed to behave like an ideal execution regardless of what runs concurrently alongside
it. However, many deployed MPC protocols are only proven secure in the stand-alone model,
and this gap has concrete exploitable consequences.

The term "concurrent" is overloaded in this context. It can mean:

- **Protocol-level concurrency**: Multiple instances of a protocol run simultaneously,
  potentially sharing state or allowing an adversary to coordinate responses across sessions.
- **Implementation-level concurrency**: A single protocol instance is executed across
  multiple threads or cooperative tasks in software, introducing race conditions not covered
  by the protocol's security model.

A multi-threaded MPC implementation may therefore need to be secure in *both* senses at once.

### Example 1: Blind Schnorr Signatures

The blind Schnorr signature scheme lets a requester obtain a valid Schnorr signature on a
blinded message without revealing the message to the signer. In a single session the scheme
is unforgeable: the signer cannot link a signature back to a particular signing request, and
the requester cannot produce a second signature it did not request.

However, when a signer participates in **multiple concurrent sessions**, a malicious requester
can coordinate across sessions to produce an *additional* signature beyond the number of
interactions—breaking *one-more unforgeability*. This follows from an efficient algorithm for
the **ROS problem** (Random inhomogeneous Systems of linear equations over Solvable groups):
[Benhamouda et al.](https://link.springer.com/article/10.1007/s00145-021-09417-3) gave a
polynomial-time algorithm that solves ROS over 256-bit elliptic curve groups using
approximately $\ell = 192$ concurrent sessions in a matter of seconds.

The adversary opens $\ell$ concurrent signing sessions with the signer. In each session $i$,
the signer commits to a nonce $R_i = k_i \cdot G$ and waits for the blinded challenge $c_i$.
The adversary chooses all $\ell$ challenges jointly so that they satisfy a linear relation
modulo the group order:
$$
\sum_{i=1}^{\ell} \rho_i \cdot c_i = c^*
$$
for some target challenge $c^*$ and known coefficients $\rho_i$. After collecting $\ell$
responses $s_i = k_i + c_i \cdot \mathsf{sk}$, the adversary combines them to produce a
valid response $s^* = \sum \rho_i \cdot s_i$ for the forged session, yielding $\ell + 1$
signatures after only $\ell$ interactions.

This vulnerability was a primary motivation for redesigning threshold Schnorr signing.
[Drijvers et al.](https://eprint.iacr.org/2018/417.pdf) showed that early multi-party
signing protocols relying on a similar structure—where each party contributes a partial
nonce and the partial signatures are aggregated—are broken by a related concurrent attack.
This directly affected the original design of FROST prior to round 2 of the IETF
standardization process. The [FROST RFC](https://github.com/cfrg/draft-irtf-cfrg-frost)
addresses this structurally via a *binding factor*: each participant's response is bound to
the specific message and the full commitment list for that signing round, making it
impossible to combine responses across concurrent sessions.

### Example 2: MP-SPDZ MAC Check Under Multi-Threading

In SPDZ, parties hold additively secret-shared values together with BDOZ MACs, and a MAC
check sub-protocol is used to verify that reconstructed values are correct before output.
The MAC check protocol is secure when run sequentially—but the UC security model used to
analyze SPDZ assumes a single-threaded execution environment.

The paper [*Rushing at SPDZ: On the Practical Security of Malicious MPC Implementations*](https://eprint.iacr.org/2025/789)
(IEEE S&P 2025) identified a MAC key leakage that can be exploited when two threads
simultaneously run an instance of the MAC check. This allows a malicious party running a
modified client to fully control the output of the computation in one thread, breaking output
integrity. Three SPDZ implementations were analyzed:

| Repository | Vulnerable | Notes |
|-----------|-----------|-------|
| [data61/MP-SPDZ](https://github.com/data61/MP-SPDZ) | Yes (patched) | Fixes shipped in v0.3.3 and v0.3.7 |
| [KULeuven-COSIC/SCALE-MAMBA](https://github.com/KULeuven-COSIC/SCALE-MAMBA) | Yes | No public patch commit; uses quarterly private release cycle |
| [aicis/fresco](https://github.com/aicis/fresco) | No | Does not support cross-thread secret transfer by design |

Two concrete bugs were found and patched in MP-SPDZ.

**Bug 1 — Missing MAC check in multi-threaded `POpen`**
([commit `5e714b2`](https://github.com/data61/MP-SPDZ/commit/5e714b2), July 2023):

The `SubProcessor<T>::POpen()` function opens secret values. The MAC verification call
`check()` was only triggered by an explicit output-gate condition (`inst.get_n()`), so in
multi-threaded programs the opened values were never MAC-checked before use:

```cpp
// FILE: Processor/Processor.hpp (vulnerable, prior to fix)

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
// FILE: Processor/Processor.hpp (fixed)

if (inst.get_n() or BaseMachine::s().nthreads > 0)
{
    C[*it + i] = MC.finalize_open();
    if (inst.get_n() or BaseMachine::s().nthreads > 0)
        check();
}
```

**Bug 2 — Race condition in `Commit_And_Open_`**
([commit `b86f29b`](https://github.com/data61/MP-SPDZ/commit/b86f29b)):

Inside `Tools/Subroutines.cpp`, the coordinator was signaled as finished *before* the
commitment-opening validation loop ran. A second thread waiting on the coordinator could
therefore observe the "finished" state and proceed with values that had not yet been
verified:

```cpp
// FILE: Tools/Subroutines.cpp (vulnerable)

P.Broadcast_Receive(Open_data);
coordinator.finished();                    // ← signals completion before verifying

for (int i = 0; i < P.num_players(); i++)
    if (!Open(datas[i], Comm_data[i], Open_data[i], i))
        throw invalid_commitment();
```

The fix moves the signal to after the validation loop:

```cpp
// FILE: Tools/Subroutines.cpp (fixed)

P.Broadcast_Receive(Open_data);
for (int i = 0; i < P.num_players(); i++)
    if (!Open(datas[i], Comm_data[i], Open_data[i], i))
        throw invalid_commitment();

coordinator.finished();                    // ← now after verifying
```

**Attack.**
Because `coordinator.finished()` fires before the validation loop, a malicious party
controlling Thread B can observe that Thread A's coordinator has finished and immediately
proceed to use the opened values in its own MAC check instance, before A has confirmed those
values are correctly authenticated. By carefully timing two concurrent MAC check instances,
the adversary extracts information about the global MAC key $\alpha$ through the
unauthenticated intermediate state, then uses this to forge MACs on arbitrary output values.

### Commits Timeline

| Date | Repository | Commit | Description |
|------|-----------|--------|-------------|
| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| Nov 2018 | — | [eprint 2018/417](https://eprint.iacr.org/2018/417) | Drijvers et al. publish concurrent attack on two-round multi-signatures, breaking early threshold Schnorr designs |
| May 2019 | — | [IEEE S&P 2019](https://www.usenix.org/system/files/sec20-drijvers.pdf) | Drijvers et al. paper presented; motivates FROST redesign to avoid concurrent nonce aggregation |
| Jul 2020 | [cfrg/draft-irtf-cfrg-frost](https://github.com/cfrg/draft-irtf-cfrg-frost) | [eprint 2020/852](https://eprint.iacr.org/2020/852) | FROST published with binding factor protecting against concurrent signing forgery |
| 2021 | — | [Journal of Cryptology](https://link.springer.com/article/10.1007/s00145-022-09436-0) | Benhamouda et al. prove ROS is poly-time solvable (~192 sessions on 256-bit curves), formally breaking blind Schnorr in concurrent settings |
| Aug 25, 2022 | [data61/MP-SPDZ](https://github.com/data61/MP-SPDZ) | [`6a42453`](https://github.com/data61/MP-SPDZ/commit/6a42453) (v0.3.3) | First MAC check multithreading fix: add `MAC_Check::setup` / `teardown` in BMR protocol threads |
| Jul 19, 2023 | [data61/MP-SPDZ](https://github.com/data61/MP-SPDZ) | [`5e714b2`](https://github.com/data61/MP-SPDZ/commit/5e714b2) | Security bug: `check()` not called in `POpen` when `nthreads > 0`; opened values left unverified in multi-threaded programs |
| Jul 21, 2023 | [data61/MP-SPDZ](https://github.com/data61/MP-SPDZ) | [`b86f29b`](https://github.com/data61/MP-SPDZ/commit/b86f29b) | Security bug: race condition in `Commit_And_Open_`; `coordinator.finished()` called before commitment validation loop |
| Aug 14, 2023 | [data61/MP-SPDZ](https://github.com/data61/MP-SPDZ) | v0.3.7 release | Both July 2023 fixes shipped; all commits after `e08a6ad` are patched |
| May 2025 | [data61/MP-SPDZ](https://github.com/data61/MP-SPDZ) · [KULeuven-COSIC/SCALE-MAMBA](https://github.com/KULeuven-COSIC/SCALE-MAMBA) | [IEEE S&P 2025](https://eprint.iacr.org/2025/789) | *Rushing at SPDZ* formally describes MAC key leakage attack; both frameworks confirmed vulnerable |
