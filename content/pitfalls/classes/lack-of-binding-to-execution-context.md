---
title: "Lack of Context Binding"
class: lack-of-context-binding
intro: true
order: 2
---

*Zero-knowledge proofs, commitments, and signatures are important building blocks of MPC protocols, especially in threshold cryptography, which is a major category of MPC. An adversary can try to replay or transplant such artifacts from one context into another: across separate runs of the protocol (sequential or concurrent), or within a single execution (e.g. across rounds, or claiming another party's message as its own). To prevent this, cryptographic artifacts (transcripts, commitments, signed messages) must bind uniquely to their execution context (session, parties, role, statement), so that witnesses, openings, and proofs cannot be reused across contexts.*
