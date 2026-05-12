---
title: "Input Validation"
class: "Input Validation"
intro: true
order: 1
---

*In MPC protocols, parties exchange data encoded as bitstrings representing mathematical objects such as field elements, group elements, commitments and proofs. A corrupted party may supply anything, so the receiver must verify that each incoming value has the expected shape, decodes to a valid object of the expected algebraic type, and lies in the required domain. The pitfalls below arise when one of these checks is omitted, applied only to the encoding, or performed in the wrong algebraic domain.*
