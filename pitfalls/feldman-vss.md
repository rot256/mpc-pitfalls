---
title: "Feldman Verified Secret Sharing"
class: "Cryptographic Primitive"
order: 14
---

- If parties do not check the length of the verification values, a malicious party can send a longer vector (which corresponds to a higher-degree polynomial). They can use this to [surreptitiously raise the threshold](https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/), preventing honest users from using the key.
- Rogue key attacks: if at least one of the following mitigations is not implemented, a malicious party can fix the shared private key to one that they know after seeing the inputs of all other parties:
    - Force all parties to commit to their inputs before revealing anything
    - Force parties to prove knowledge of their secret contributions (in zero knowledge)
