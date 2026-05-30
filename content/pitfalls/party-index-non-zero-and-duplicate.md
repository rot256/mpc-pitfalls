---
title: "Parties' Shares Not Validated as Non-Zero and Distinct"
class: input-validation
hidden: false
order: 1
source: "shamir-secret-sharing.md"
primitives: [secret-sharing]
---


**What can go wrong.** 
Many MPC protocols build upon Shamir secret sharing, a $(t, n)$-threshold scheme that recovers a secret $s = f(0)$ from $t$ shares of a sharing polynomial $f(x) = s + \sum_{i=1}^{t-1} a_i x^i$ over $\mathbb{Z}_q$, with coefficients $a_i$ drawn uniformly at random. Each party $P_i$ holds the share $(i, x_i = f(i))$, and any $t$ parties can reconstruct via $s = \sum_{j} x_j \, l_j(0)$ with Lagrange basis $l_j(0) = \prod_{k, k \ne j} \frac{x_k}{x_k - x_j}$. 
Both the index $i$ and the share $x_i$ live in $\mathbb{Z}_q$, so every implementation must reduce modulo $q$ before using them. Two related failures arise when this reduction is skipped at the input boundary.
*First*, if a party can choose its own index and the implementation rejects only the *integer* $0 \in \mathbb{Z}$, an attacker submitting $i = q$ (or any $k \cdot q$) passes the check while `evaluatePolynomial(q) ≡ evaluatePolynomial(0) = f(0) = secret`, handing it the secret directly.
*Second*, the Lagrange basis denominator $x_k - x_j$ vanishes modulo $q$ whenever any two reconstruction indices coincide mod $q$, whether as the same raw integer (naïve duplicate) or as a malicious $x_k' = x_j + q$ (distinct as `big.Int`, congruent in $\mathbb{Z}_q$). The subsequent modular inverse is undefined.

**Security implication.** A party whose index reduces to $0 \bmod q$ is handed $f(0)$, the shared secret itself: the dealer evaluates the sharing polynomial at the attacker's index and returns the result as normal. In a DKG, where every party deals a contribution, the attacker collects $f(0)$ from each dealer and reconstructs the full private key with no further interaction. The duplicate failure splits into two outcomes. In availability terms, reconstruction crashes with a nil-pointer dereference (Go's `ModInverse` returns `nil` for a non-invertible input) or throws an unrecoverable error, DoS-ing the signing ceremony. In integrity terms, some implementations silently skip the offending term or substitute a default, producing an incorrect reconstruction the caller accepts as valid.

**How to avoid.** Validate indices at the protocol's share-ingestion boundary: reduce each index modulo $q$, reject zero, and verify pairwise distinctness in a single pass.
