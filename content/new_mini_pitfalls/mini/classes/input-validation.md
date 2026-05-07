---
title: "Input Validation"
class: "Input Validation"
intro: true
order: 1
---

*In MPC protocols, parties exchange data encoded as bitstrings that represent mathematical objects such as elements of $\mathbb{Z}_q^*$, commitments to polynomial coefficients, zero-knowledge proofs, or lists of peer contributions. The protocol guarantees correct computation on whatever inputs the parties supply; it does not constrain those inputs. A corrupted party may submit any value, so if an application's security depends on well-formed inputs, the implementation must enforce that separately.*

*In secret-sharing-based MPC, the **domain of secrets**, the admissible inputs of the function, and the **domain of shares**, the algebraic structure over which the sharing scheme operates, usually do not match. For example, a one-bit boolean secret may be shared over $\mathbb{F}_p$ for a large prime $p$; a 64-bit integer is shared over $\mathbb{Z}_{2^{128}}$; a Schnorr/ECDSA message hash must lie in $\mathbb{Z}_q$. Before using an incoming message, the receiver must verify that the message has the expected shape, that each component decodes to a valid object of the expected algebraic type, and that each value satisfies the constraints of the secret or input domain. The pitfalls below arise when one of these checks is omitted, applied only to the encoding, or performed in the wrong domain.*
