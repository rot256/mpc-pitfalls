---
title: "Non-Safe-Prime Modulus"
class: cryptographic-primitives
hidden: false
order: 2
source: "discrete-log-groups.md"
primitives: [rsa, group]
bugs: [tss-lib-ntilde-safe-primes]
display: [tss-lib-ntilde-safe-primes]
---


**What can go wrong.** MPC protocols built over discrete-log groups such as $\text{QR}_p \subset \mathbb{Z}_p^*$, or $\text{QR}_N$ for an RSA modulus $N = PQ$, rely on the hardness of the discrete logarithm problem (DLP), which holds only when the group's order has a sufficiently large prime factor. The standard way to guarantee this is to use *safe primes*: a prime $p = 2q + 1$ where $q$ is also prime. Then $\lvert \text{QR}_p \rvert = q$ is a large prime, and likewise $\lvert \text{QR}_N \rvert = \phi(N)/4 = (P-1)(Q-1)/4$ is a product of two large primes when both $P, Q$ are safe primes. If an implementation feeds ordinary RSA primes into code that assumes safe primes, the generated group no longer satisfies the proof system's precondition.


**Security implication.** The downstream proof is no longer instantiated in the
group its security argument assumes. When either $\lvert \text{QR}_p \rvert =
(p-1)/2$ or $\lvert \text{QR}_N \rvert = (P-1)(Q-1)/4$ is smooth, i.e., factors
only into small primes $q_1, \ldots, q_k$ with each $q_i \lt 2^{100}$,
Pohlig-Hellman solves the DLP in time roughly
$O\bigl(\log M + \sum_i \sqrt{q_i}\bigr)$, where $M \in \{p, N\}$ (see
[Valenta et al., eprint 2016/995](https://eprint.iacr.org/2016/995.pdf) for the
canonical analysis). Protocols that use the resulting bases for DLN or
Pedersen-style proofs can lose both binding/soundness and hiding. Discrete-log
relations that should be infeasible to compute may become computable, enabling
equivocation or forged proofs. Pedersen-style commitments built from those bases
can also leak information about the committed value in the smooth-order
components of the group, especially when the committed value is range-bounded.
Thus the proof may fail both as an integrity check and as a confidentiality
mechanism. For instance, in a previous tss-lib version (see example), the
$\tilde N$ generation path used ordinary RSA primes even though the helper that
derived the DLN bases assumed $\tilde N$ was a product of safe primes, so the
DLN parameters were generated outside their documented precondition.

**How to avoid.** When a protocol or helper requires a safe-prime group, generate
$p$ (or both factors $P, Q$ of $N = PQ$) as safe primes. Do not substitute a
generic RSA prime generator for safe-prime generation. For standardized prime
groups, prefer the audited safe-prime constructions in
[RFC 3526](https://www.rfc-editor.org/rfc/rfc3526) and
[RFC 7919](https://www.rfc-editor.org/rfc/rfc7919).
