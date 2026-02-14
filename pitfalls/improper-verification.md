---
title: "Improper verification of received messages"
class: "Protocol"
order: 1
---

In MPC protocols, parties exchange mathematical objects such as 'an element from $\mathbb{Z}_q^*$', 'a commitment to the coefficients of a degree $t-1$ polynomial', or 'a list of zero-knowledge proofs'. In MPC implementations, parties exchange bitstrings over a network, and they need to verify that the received bitstring corresponds to a valid mathematical object of the expected type. Each of the following issues is commonly found in MPC implementations, affecting confidentiality, integrity, or availability:

- **The received value is not a valid element**: When receiving an element from $\mathbb{Z}_q^*$ or a similar group/ring/field, the receiver needs to check that it's non-zero. Additionally, when the element is supposed to generate a non-trivial subgroup, the receiver also needs to check that it's not 1 (or some other invalid value that does not generate the correct subgroup).
- **The received sequence of values is not the correct length**:
    - When receiving the commitments to the coefficients of a degree $t-1$ polynomial during Feldman VSS, the receiver needs to check that the length of the committed coefficient vector is equal to $t$, lest the threshold becomes higher than intended.
    - When receiving a list of zero-knowledge proofs, the receiver needs to verify that the list is not empty. Iterating over an empty list often results in accepting the proofs, as an empty list contains no incorrect proofs.
