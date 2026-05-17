---
title: "Failure Recovery and Aborts"
class: failure-recovery-and-abort-handling
intro: true
order: 5
---

*When a subprotocol detects a consistency failure, the implementation must surface that
failure in a form the caller can act on. Structured terminal errors, diagnostic mismatch
signals, and coordinated cancellation prevent honest parties from misdiagnosing
configuration failures as attacks or retrying with compromised state.*
