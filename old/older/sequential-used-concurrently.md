---
title: "Sequentially Secure Protocol Used Concurrently"
class: "Sequentially Secure Protocol Used Concurrently"
order: 7
---

Many MPC protocols are proven secure only in the
[*stand-alone setting*](https://eprint.iacr.org/1998/018): the protocol may run as a
sub-protocol with arbitrary messages before and after, but no other messages may be
sent in parallel during its execution. Running a stand-alone-proven protocol
concurrently breaks that proof, and the gap has concrete, exploitable consequences.
(The adjacent *UC Setup Assumptions Not Realized* category above covers a different
composition concern: the deployment failing to provide the channels and session setup
a UC proof assumed.)

The word "concurrent" is overloaded. **Protocol-level concurrency** means multiple
instances of the protocol run simultaneously, potentially sharing state or letting an
adversary coordinate responses across sessions. **Implementation-level concurrency**
means a single protocol instance executes across multiple threads or cooperative tasks,
introducing race conditions that the protocol's security model does not cover. A
multi-threaded MPC implementation may need to be secure in both senses at once.

### Blind Schnorr signatures used concurrently (ROS attack)

**What can go wrong.** The blind Schnorr signature scheme is provably one-more
unforgeable in a *single* session but not under concurrent signing. A signer that
participates in $\ell$ concurrent sessions exposes all nonce commitments $R_i$ to the
requester before it ever commits to the challenges $c_i$. If the requester can choose
all $\ell$ challenges *after* seeing all $R_i$, it can set them to satisfy a linear
relation (the ROS relation) that lets it combine the $\ell$ partial responses into an
$(\ell + 1)$-th, unrequested signature. The same structural gap broke early threshold
Schnorr designs in which each party contributes a partial nonce and the partial
signatures are aggregated without session binding.

**Security implication.** [Benhamouda et al.](https://link.springer.com/article/10.1007/s00145-021-09417-3)
gave a polynomial-time algorithm for ROS that solves the problem over 256-bit
elliptic-curve groups using approximately $\ell = 192$ concurrent sessions in a matter
of seconds. After collecting responses from those sessions the adversary produces one
extra signature — breaking one-more unforgeability. In threshold-signing deployments
this translates directly to unauthorised signatures on attacker-chosen messages: keys
that were supposed to require threshold cooperation can be used to sign arbitrary
payloads.

**How to avoid.** Two complementary approaches.

*Structural.* Bind each challenge to the session's specific nonce commitment and
message so the adversary cannot freely choose challenges after observing the nonces.
FROST achieves this with a per-participant binding factor, standardized in
[RFC 9591](https://datatracker.ietf.org/doc/html/rfc9591) (June 2024). MuSig2
([Nick et al., CRYPTO 2021](https://eprint.iacr.org/2020/1261)) uses two aggregated
nonces per session whose specific linear combination is provably secure under
concurrent execution.

*Application-layer serialisation.* If the protocol itself cannot be changed, the signer
must complete or abort one session before starting another, preventing the
$\ell \approx 192$ sessions required to solve ROS from being open simultaneously.

**Example: Drijvers et al. concurrent attack on two-round multi-signatures.** The
vulnerable two-round blind Schnorr signer accepts challenges from the requester without
any session binding:

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
signer, then chooses all $\ell$ challenges *jointly* so they satisfy the ROS relation
$\sum_{i=1}^{\ell} \rho_i \cdot c_i = c^* \pmod{q}$ for a target challenge $c^*$ and
known coefficients $\rho_i$. After collecting $\ell$ responses $s_i = k_i + c_i \cdot
\mathsf{sk}$, the adversary combines them:
$$s^* = \sum_{i=1}^{\ell} \rho_i \cdot s_i = \sum \rho_i k_i + \left(\sum \rho_i c_i\right) \mathsf{sk} = R^* + c^* \cdot \mathsf{sk}$$
yielding a valid signature $(R^*, s^*)$ on a message the signer never individually
signed. [Drijvers et al.](https://eprint.iacr.org/2018/417.pdf) showed that early
threshold Schnorr protocols — where each party contributes a partial nonce and the
partial signatures are aggregated without session binding — break under the same attack.
This directly affected the original design of FROST prior to round 2 of the IETF
standardization process. The fix:

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

-->
