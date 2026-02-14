---
title: "Fiat-Shamir"
class: "Cryptographic Primitive"
order: 11
---

- The witness domain is not large enough to not allow for computational brute-forcing, i.e. has less than 128 bits of entropy.
- Randomness used does not contain at least 128 bits of entropy.
- The transcript used to generate challenges does not include all required values, including but not limited to the public input and the problem statement ([weak Fiat-Shamir](https://eprint.iacr.org/2020/1052.pdf)).
