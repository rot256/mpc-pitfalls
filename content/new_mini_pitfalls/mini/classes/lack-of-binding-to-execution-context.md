---
title: "Lack of Context Binding"
class: "Lack of Context Binding"
intro: true
order: 2
---

*Zero-knowledge proofs and commitments are important building blocks of MPC protocols, especially in threshold cryptography, which is a major category of MPC. Given multiple runs of the protocol (sequential or concurrent), an adversary can try to replay or transplant artifacts from one context into another. To prevent this, cryptographic artifacts (transcripts, commitments, signed messages) must bind uniquely to their execution context (session, parties, role, statement), so that witnesses, openings, and proofs cannot be reused across contexts. The following pitfalls arise when these primitives are not properly bound to their execution context.*
