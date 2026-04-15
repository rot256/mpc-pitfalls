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

The following pseudocode shows the vulnerable two-round blind Schnorr signer, which accepts
challenges from the requester without any session binding:

```python
# Vulnerable blind Schnorr signer — no binding between nonce and challenge
class BlindSchnorrSigner:
    def round1(self) -> Point:
        self.k = random_scalar()          # fresh nonce per session
        self.R = self.k * G               # nonce commitment
        return self.R                     # sent to requester

    def round2(self, c: Scalar) -> Scalar:
        # c arrives from the requester with no proof it was derived from
        # this specific R or from any particular message.
        # A malicious requester can choose c freely — including as a
        # linear combination of challenges from other concurrent sessions.
        s = self.k + c * self.sk          # partial response
        return s
```

The requester accumulates $\ell$ sessions. In each session $i$ it receives $R_i$ from the
signer, then chooses all $\ell$ challenges *jointly* so that they satisfy the ROS relation:
$$
\sum_{i=1}^{\ell} \rho_i \cdot c_i = c^* \pmod{q}
$$
for a target challenge $c^*$ and known coefficients $\rho_i$. After collecting $\ell$
responses $s_i = k_i + c_i \cdot \mathsf{sk}$, the adversary combines them:
$$
s^* = \sum_{i=1}^{\ell} \rho_i \cdot s_i
  = \sum \rho_i k_i + \left(\sum \rho_i c_i\right) \mathsf{sk}
  = R^* + c^* \cdot \mathsf{sk}
$$
yielding a valid signature $(R^*, s^*)$ on a message the signer never individually signed —
$\ell + 1$ signatures after only $\ell$ interactions.

This vulnerability was a primary motivation for redesigning threshold Schnorr signing.
[Drijvers et al.](https://eprint.iacr.org/2018/417.pdf) showed that early multi-party
signing protocols relying on a similar structure — where each party contributes a partial
nonce and the partial signatures are aggregated without session binding — are broken by the
same concurrent attack. This directly affected the original design of FROST prior to round 2
of the IETF standardization process.

**Remediation.** There are two complementary approaches.

The first is **structural**: bind each challenge to the specific session's nonce and message
so that the adversary cannot freely choose it after observing all nonces. FROST achieves this
by computing a per-participant binding factor before any response is produced:

```python
# Fixed: FROST-style binding factor prevents cross-session combination
class FROSTSigner:
    def round1(self) -> Point:
        self.k = random_scalar()
        self.R = self.k * G
        return self.R

    def round2(self, msg: bytes, commitments_list: list[Point],
               participant_index: int) -> Scalar:
        # Binding factor ties this response to the exact (msg, commitment_list, index)
        # tuple. A response from a different session has a different rho and cannot
        # be linearly combined with this one.
        rho = H(msg, commitments_list, participant_index)   # binding factor
        R_agg = sum(rho_j * R_j for rho_j, R_j in zip(rhos, commitments_list))
        c = H(R_agg, msg)                                  # Fiat-Shamir challenge

        s = self.k + rho * c * self.sk    # response bound to this session only
        return s
```

The [FROST RFC 9591](https://datatracker.ietf.org/doc/html/rfc9591) (published June 2024)
standardizes this construction. The second approach, suitable when the protocol cannot be
changed, is to **limit concurrency at the application layer**: the signer must complete or
abort an existing session before starting a new one, preventing the adversary from
accumulating the $\ell \approx 192$ concurrent sessions required to solve ROS. MuSig2
([Nick et al., CRYPTO 2021](https://eprint.iacr.org/2020/1261)) takes a middle path: it
uses two aggregated nonces per session whose specific linear combination is provably secure
under concurrent execution without sequentialization.

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
multi-threaded programs the opened values were never MAC-checked before use
([source](https://github.com/data61/MP-SPDZ/commit/5e714b2)):

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

The fix extends both conditions to also fire when threads are active ([source](https://github.com/data61/MP-SPDZ/blob/5e714b2/Processor/Processor.hpp)):

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
verified ([source](https://github.com/data61/MP-SPDZ/commit/b86f29b)):

```cpp
// FILE: Tools/Subroutines.cpp (vulnerable)

P.Broadcast_Receive(Open_data);
coordinator.finished();                    // ← signals completion before verifying

for (int i = 0; i < P.num_players(); i++)
    if (!Open(datas[i], Comm_data[i], Open_data[i], i))
        throw invalid_commitment();
```

The fix moves the signal to after the validation loop ([source](https://github.com/data61/MP-SPDZ/blob/b86f29b/Tools/Subroutines.cpp)):

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

**Remediation.** The MAC check sub-protocol must be treated as an **atomic critical section**
across all threads. This means:

1. **Mutual exclusion on the MAC check itself.** A mutex or semaphore must prevent two threads
   from executing overlapping instances of the MAC check (including the possible abort path).
   In MP-SPDZ, this is now enforced via the coordinator signal ordering fix in commit
   [`b86f29b`](https://github.com/data61/MP-SPDZ/commit/b86f29b): `coordinator.finished()`
   is called only *after* the full commitment-opening validation loop completes.

2. **Unconditional MAC verification on `POpen`.** The `check()` call must fire whenever
   values are opened, regardless of whether the opened values reach an output gate. Commit
   [`5e714b2`](https://github.com/data61/MP-SPDZ/commit/5e714b2) extends the condition from
   `inst.get_n()` to `inst.get_n() or BaseMachine::s().nthreads > 0`, closing the gap where
   multi-threaded programs could open and use values that had never been MAC-checked.

3. **Design-level isolation.** Where possible, avoid sharing secret state across threads
   entirely. The Fresco framework is not affected by either bug because it does not support
   cross-thread secret transfer by design — a useful reference point for new implementations.

### Commits Timeline

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

### Real-World Impact

**FROST before IETF round 2 (2020–2021).** The original FROST paper
([Komlo & Goldberg, SAC 2020](https://eprint.iacr.org/2020/852)) was published alongside the
finding by Drijvers et al. that its predecessor designs were broken under concurrent signing.
Before the binding-factor mechanism was introduced in the IETF draft, several early
open-source FROST implementations (including reference implementations for the Zcash and
Privacy Pass ecosystems) were based on the earlier nonce-aggregation design. While no
on-chain exploit has been confirmed, the Zcash Foundation and the CFRG working group both
treated the concurrent-security gap as a blocking issue, requiring the protocol to be
redesigned before any threshold wallet deployed it in production. The binding factor became
mandatory in [draft-irtf-cfrg-frost-08](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-frost-08)
and was eventually standardized in [RFC 9591](https://datatracker.ietf.org/doc/html/rfc9591)
(June 2024).

**MuSig1 (2018–2020).** The original MuSig multi-signature scheme
([Maxwell et al., 2018](https://eprint.iacr.org/2018/068)) suffered from the same
Drijvers et al. concurrent attack. Because MuSig1 was primarily a research proposal at the
time the attack was published, no known production deployment used the vulnerable two-round
variant. The attack prompted the design of **MuSig2**
([Nick et al., CRYPTO 2021](https://eprint.iacr.org/2020/1261)), which achieves concurrent
security by introducing a second aggregated nonce per session, making it the basis for all
subsequent Bitcoin Schnorr multi-signature deployments (e.g., in Lightning Network channel
management and BIP-327).

**MP-SPDZ / SCALE-MAMBA (2022–2025).** Both frameworks are used in academic research
prototypes and in commercial MPC-as-a-service deployments for privacy-preserving analytics
and secure collaborative computation. MP-SPDZ shipped patches in v0.3.3 (August 2022) and
v0.3.7 (August 2023) addressing the two threading bugs. SCALE-MAMBA, by contrast, has no
public patch commit and distributes updates via a quarterly private release cycle — meaning
any deployment using a SCALE-MAMBA build prior to the private fix remains vulnerable with no
public indicator of when or whether the fix was applied. The *Rushing at SPDZ* paper (IEEE
S&P 2025) confirmed that the attack is practical: in their proof-of-concept a malicious client
running a modified binary fully controls the output of a concurrent thread's computation,
breaking the malicious-security guarantee that SPDZ is specifically designed to provide.

