---
title: "RSA-Style Moduli"
class: "Cryptographic Primitive"
order: 6
---

- Not validating that the private key $d>N^{\frac{1}{4}}$.
- Not validating that a base element has order 2 or 4.

#### Recommendations

When used in custom protocols it is strongly recommended to ensure the following as well:

- $p$ and $q$ are safe primes.
- $p$ and $q$ are strong primes.
- If the group is used for signatures, then PSS padding is used.
- If the group is used for encryption then OAEP is used.
