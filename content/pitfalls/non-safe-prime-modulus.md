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


**What can go wrong.** MPC protocols built over discrete-log groups such as $\text{QR}_p \subset \mathbb{Z}_p^*$, or $\text{QR}_N$ for an RSA modulus $N = PQ$, rely on the hardness of the discrete logarithm problem (DLP), which holds only when the group's order has a sufficiently large prime factor. The standard way to guarantee this is to use *safe primes*: a prime $p = 2q + 1$ where $q$ is also prime. Then $\lvert \text{QR}_p \rvert = q$ is a large prime, and likewise $\lvert \text{QR}_N \rvert = \phi(N)/4 = (P-1)(Q-1)/4$ is a product of two large primes when both $P, Q$ are safe primes. Without that guarantee, an adversary can choose the modulus so that the DLP is easy.



**Security implication.** When $\lvert \text{QR}_p \rvert = (p-1)/2$ or $\lvert \text{QR}_N \rvert = (P-1)(Q-1)/4$ are smooth, i.e, factors only into small primes (i.e each $q_i \lt 2^{100}$ bits) $q_1, \ldots, q_k$, Pohlig-Hellman solves the DLP in time roughly $O\bigl(\log M + \sum_i \sqrt{q_i}\bigr)$, where $M \in \{p, N\}$ (see [Valenta et al., eprint 2016/995](https://eprint.iacr.org/2016/995.pdf) for the canonical analysis). For tss-lib's Pedersen bases $h_1, h_2 \in \text{QR}_{\tilde N}$, an adversary who factors $\tilde N$ recovers $\log_{h_1}(h_2)$ via Pohlig-Hellman and extracts the DLN proof's witness without performing honest keygen, undermining the zero-knowledge property of every range proof built on those bases.

**How to avoid.** Generate $p$ (or both factors $P, Q$ of $N = PQ$) as safe primes. For standardized prime groups, prefer the audited safe-prime constructions in [RFC 3526](https://www.rfc-editor.org/rfc/rfc3526) and [RFC 7919](https://www.rfc-editor.org/rfc/rfc7919).