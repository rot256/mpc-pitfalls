---
title: "Failure Recovery and Abort Handling"
class: "Failure Recovery and Abort Handling"
intro: true
order: 6
---

*When a subprotocol detects a consistency failure, the implementation must surface that
failure in a form the caller can act on. Structured terminal errors, diagnostic mismatch
signals, and coordinated cancellation prevent honest parties from misdiagnosing
configuration failures as attacks or retrying with compromised state.*
