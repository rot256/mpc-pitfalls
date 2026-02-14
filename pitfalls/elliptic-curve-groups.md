---
title: "Elliptic curve groups"
class: "Cryptographic Primitive"
order: 8
---

- Not ensuring that the co-factor of the curve is 1 _or_ all base elements are validated to live in the large subgroup.
- Anything selected by a potentially malicious party (e.g. client) is not validated to be a valid point on the curve (_not_ infinity) _and_ potentially living in the large subgroup in case of co-factor different from 1.
- Not using a curve hashing algorithm for hashing to the curve. That is, hashing an element to a random $x$ coordinate and computing the $y$ coordinate is likely not going to be secure. See [this paper](https://eprint.iacr.org/2022/759.pdf) for details.
