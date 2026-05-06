---
title: "Randomness has insufficient entropy"
class: "Others"
source: "fiat-shamir.md"
---

### Randomness has insufficient entropy

<!--div class="pitfall-flags"><span class="flag flag-tbd">TBD example</span></div-->

**What can go wrong.** Sigma protocols require the prover to sample fresh commitment
randomness $r$ for each run. If that randomness has fewer than ~128 bits of entropy —
or is reused across proofs, or is derived from an observable source — the secret
witness can be extracted algebraically from one or a few proofs. This is the same class
as the classical ECDSA nonce-reuse attack, generalised to any FS-based sigma proof.

**Security implication.** A passive observer who can infer or predict the prover's
randomness recovers the secret after observing one or a few proofs. For threshold
signing, a single signer with a weak RNG leaks its share across signatures. For DLN or
range proofs on Paillier parameters, weak randomness can leak the Paillier prime
factorisation. No protocol-level misbehaviour is required; the RNG weakness alone is
enough.

**How to avoid.** Draw all protocol randomness from a cryptographically secure RNG that
provides at least 128 bits of entropy per call. If using a deterministic FS variant
(nonce derived from the secret and the message), follow the construction in
[RFC 6979](https://www.rfc-editor.org/rfc/rfc6979); never reuse commitment randomness
across proofs.

<!--**Example.** *TBD.* RNG weaknesses are common audit findings but no MPC-specific CVE is
pinned to this page yet.
-->

**Example: MP-SPDZ FKOS15 input randomization narrower than claimed ([commit `99c5efc`](https://github.com/data61/MP-SPDZ/commit/99c5efc115ab1dfe8acfffad1997a2735ed766ac), Oct 13 2020).**
FKOS15 (Frederiksen–Keller–Orsini–Scholl 2015) is the MPC-with-preprocessing protocol
underlying MASCOT and SPDZ2k. Party inputs are masked with preprocessed correlated
randomness; the security argument requires that mask to carry the full claimed
statistical-security parameter of entropy. In MP-SPDZ before October 2020,
`Tools/BitVector.h::randomize_blocks` produced under-randomized masks for single-bit
input types: the loop drove `tmp.randomize(G)` once per `T`-sized block, but for a 1-bit
`T` that path did not place fresh PRG output across every byte of the underlying buffer
([source](https://github.com/data61/MP-SPDZ/blob/bd3366a0bb6f086bed876ec94c3288992c96bd39/Tools/BitVector.h#L305-L313)):

```cpp
// Tools/BitVector.h — data61/MP-SPDZ (vulnerable, pre-99c5efc)
template<class T>
inline void BitVector::randomize_blocks(PRNG& G)
{
    T tmp;
    for (size_t i = 0; i < (nbytes / T::size()); i++)
    {
        tmp.randomize(G);                                        // biased for 1-bit T
        memcpy(bytes + i * T::size(), tmp.get_ptr(), T::size());
    }
}
```

The fix special-cases the 1-bit case to fill the buffer directly from the PRG, so the
mask gets full per-bit entropy rather than the under-populated bits the original loop
produced:

```cpp
// Tools/BitVector.h — data61/MP-SPDZ (fixed, 99c5efc)
template<class T>
inline void BitVector::randomize_blocks(PRNG& G)
{
    if (T::size_in_bits() == 1)
    {
        G.get_octets(bytes, nbytes);                             // raw PRG output
    }
    else
    {
        T tmp;
        for (size_t i = 0; i < (nbytes / T::size()); i++)
        {
            tmp.randomize(G);
            memcpy(bytes + i * T::size(), tmp.get_ptr(), T::size());
        }
    }
}
```

A malicious party who observes the masked input transcript can narrow the search space
for the honest party's bit-input by exploiting the mask's reduced effective entropy: the
soundness of FKOS15's input authentication assumed the mask hid the input
information-theoretically up to $2^{-s}$, but the under-randomized mask collapsed that
guarantee to a smaller margin. The patch restores the claimed statistical security; the
fix landed as a single commit in October 2020 with the explicit subject *"Security bug:
insufficient randomization of FKOS15 inputs."*
