---
title: "MP-SPDZ FKOS15 `randomize_blocks`"
date: 2020-10-13
primitives: [randomness, secret-sharing]
repository: https://github.com/data61/MP-SPDZ
commit: 99c5efc115ab1dfe8acfffad1997a2735ed766ac
---

FKOS15 is the MPC-with-preprocessing protocol underlying MASCOT and SPDZ2k. Party inputs are masked with preprocessed correlated randomness; the security argument requires that mask to carry the full claimed statistical-security parameter of entropy. 

In MP-SPDZ pre-fix, `Tools/BitVector.h::randomize_blocks` produced under-randomized masks for single-bit input types: the loop drove `tmp.randomize(G)` once per `T`-sized block, but for a 1-bit `T` that path did not place fresh PRG output across every byte of the underlying buffer ([source](https://github.com/data61/MP-SPDZ/blob/bd3366a0bb6f086bed876ec94c3288992c96bd39/Tools/BitVector.h#L305-L313)):

```cpp
// Tools/BitVector.h — data61/MP-SPDZ (vulnerable, pre-99c5efc)
template<class T>
inline void BitVector::randomize_blocks(PRNG& G)
{
    T tmp;
    for (size_t i = 0; i < (nbytes / T::size()); i++)
    {
        tmp.randomize(G);                            // biased for 1-bit T
        memcpy(bytes + i * T::size(), tmp.get_ptr(), T::size());
    }
}
```
A malicious party who observes the masked input transcript can narrow the search space for the honest party's bit-input by exploiting the mask's reduced effective entropy: the soundness of FKOS15's input authentication assumed the mask hid the input information-theoretically up to $2^{-s}$, but the under-randomized mask collapsed that guarantee to a smaller margin.

The fix special-cases the 1-bit case to fill the buffer directly from the PRG, so the mask gets full per-bit entropy rather than the under-populated bits the original loop produced ([source](https://github.com/data61/MP-SPDZ/blob/99c5efc115ab1dfe8acfffad1997a2735ed766ac/Tools/BitVector.h#L305-L321)):

```cpp
// Tools/BitVector.h — data61/MP-SPDZ (fixed, 99c5efc)
template<class T>
inline void BitVector::randomize_blocks(PRNG& G)
{
    if (T::size_in_bits() == 1)
    {
        G.get_octets(bytes, nbytes);                 // raw PRG output
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