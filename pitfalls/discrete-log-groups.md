---
title: "Discrete log groups"
class: "Cryptographic Primitive"
order: 7
---

- The group is not defined from a safe prime $p=2q+1$.
- Anything, $x$, selected by a potentially malicious party (e.g. client) is not validated to live in the secure subgroup before usage. I.e. $1 \equiv x^q \mod p$ for $p=2q+1$.
- Missing validation that any group generator $g$ is different from $\pm 1 \mod p$ and $g^{\frac{p-1}{2}} \equiv 1 \mod p$. (This is needed to ensure that elements live in the subgroup of q elements. Note that this is needed to avoid lsb of exponent being leaked, which happens when using the full group. An alternative approach is to just square everything. See [this paper](https://eprint.iacr.org/2016/995.pdf) for details.)
