---
title: "Failure Recovery and Aborts"
class: failure-recovery-and-abort-handling
intro: false
order: 5
---

*When a protocol aborts, whether for benign or malicious reasons, the implementation must ensure that the failures are handled securely. What securely means is protocol-specific and may vary from: simply rerunning the protocol, removing a corrupted party, restarting other parts of the protocol, discarding some correlated randomness, or never running the protocol with the same input again.*
