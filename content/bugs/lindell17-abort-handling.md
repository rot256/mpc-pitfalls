---
title: "Lindell17 two-party ECDSA"
category: failure-recovery-and-abort-handling
subcategory: "Selective-Abort Attacks during OT Extension"
date: 2023-08-09
primitives: [signature, paillier, homomorphic-encryption]
source:
  - name: "Fireblocks, 2023"
    url: https://www.fireblocks.com/blog/lindell17-abort-vulnerability-technical-report
cve:
  name: CVE-2023-33242
  url: https://nvd.nist.gov/vuln/detail/CVE-2023-33242
hidden: false
---

Lindell's two-party ECDSA ([Lindell, 2017](https://eprint.iacr.org/2017/552)) splits the
signing key between a client and a server using Paillier homomorphic encryption, with no
oblivious transfer involved. Its security analysis requires that a signatory **abort and
stop signing** the moment a produced signature fails to verify; the abort must be terminal.

[Fireblocks](https://www.fireblocks.com/blog/lindell17-abort-vulnerability-technical-report)
found that real deployments deviated from this, treating a failed signature as an ordinary,
retryable error and continuing to sign with the same key. A party that has compromised its
counterparty crafts a malformed Paillier ciphertext so that signature generation succeeds
only when the least-significant bit of the honest party's secret share is zero. Each request
then leaks one bit through success-or-abort, and the full key is recovered after a few
hundred signatures.

The fix makes the failed-signature abort terminal and distinguishable from benign aborts such as timeouts, or adds a zero-knowledge proof on the client's final message.
