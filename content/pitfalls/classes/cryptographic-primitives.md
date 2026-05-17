---
title: "Cryptographic Primitives"
class: cryptographic-primitives
intro: true
order: 8
---

*The preceding classes concern how an MPC protocol wires its primitives together. The pitfalls here concern the primitives themselves: a modulus that is not a safe prime, a Paillier key with small factors, a hash used where it offers no domain separation, randomness drawn from too small a space. Each is a failure in the choice or construction of a building block, independent of the protocol wrapping it. We collect them here because the fix is local to the primitive, and the same checklist applies regardless of which protocol is being audited.*
