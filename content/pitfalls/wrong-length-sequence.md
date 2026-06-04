---
title: "Received Sequence Has the Wrong Length"
class: input-validation
hidden: false
order: 4
source: "improper-verification.md"
primitives: [secret-sharing, commitment]
bugs: [wsts-threshold-raise]
display: [wsts-threshold-raise]
---


**What can go wrong.** MPC protocols often handle sequences with an expected length such as Feldman VSS commitment vectors of length $t$, lists of $n-1$ peer signatures, or vectors of DLN proof iterations. Each carries a protocol-specified length that the verifier must check before using the sequence. Accepting a sequence with an unexpected shape is functionally running a different protocol instance from the one the verifier thought it was in. The same bug also appears at the lower bound: an empty proof, signature, or participant list can make a verification loop execute zero times and return success vacuously unless the expected length is checked first.

**Security implication.** In the context of DKG (Distributed Key Generation), a malicious party can send a Feldman VSS commitment vector of length $t + k$ while the protocol-specified length is $t$. Honest verifiers iterate over all $t + k$ elements without noticing the mismatch, [surreptitiously raising the reconstruction threshold](https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/) from $t$ to $t + k$ and leaving the shared key irrecoverable from the $t$ honest shares alone, unless the DKG is restarted from scratch.

**How to avoid.** Each party must compare the received vector length against the protocol-specified length before using the vector and abort the protocol on any length mismatch.